/*
 * StorFuzzPass.cc — StorFuzz data-flow coverage, LLVM 11 Legacy Pass Manager
 *
 * Adapted from StorFuzz-LibAFL/libafl_cc/src/storfuzz-coverage-pass.cc
 *
 * Changes from upstream source
 * ----------------------------
 *  - Legacy PM only (no USE_NEW_PM paths).
 *  - LLVM 11 typed-pointer API: untyped CreateLoad/CreateGEP, no MaybeAlign
 *    argument to CreateAtomicRMW, startswith() not starts_with(), isa<A>()||
 *    isa<B>() instead of variadic isa<A,B>(), no PseudoProbeInst.
 *  - Map global renamed __storfuzz_area_ptr → __angora_data_area_ptr to match
 *    Angora's ANGORA_* naming convention.
 *  - LoopInfo unavailable without explicit analysis request; set to nullptr
 *    (disables loop-counter detection — conservative, still correct).
 *  - maybeWeakenFunction removed (LibAFL in-process artefact, not needed for
 *    fork-server fuzzing).
 *  - LazyValueInfo / LVI removed (only used inside new-PM path).
 *  - STORFUZZ_VERBOSE env-var gates per-module count printed to stderr.
 *  - STORFUZZ_MAP_SIZE defaults to 1<<17 if not defined at compile time.
 *  - RandBelow() defined inline (from common-llvm.h).
 */

#include <fcntl.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <string>

#include "llvm/ADT/DenseMap.h"
#include "llvm/Analysis/LoopInfo.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/LegacyPassManager.h"
#include "llvm/IR/MDBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/Pass.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/IPO/PassManagerBuilder.h"

#ifndef STORFUZZ_MAP_SIZE
#define STORFUZZ_MAP_SIZE (1 << 17)
#endif

using namespace llvm;

/* Simple rand wrapper identical to common-llvm.h */
static uint32_t RandBelow(uint32_t max) {
  return (uint32_t)rand() % max;
}

namespace {

class StorFuzzCoverage : public ModulePass {
 public:
  static char ID;

  StorFuzzCoverage() : ModulePass(ID) {}

  bool runOnModule(Module &M) override;

 protected:
  uint32_t map_size             = STORFUZZ_MAP_SIZE;
  uint32_t function_minimum_size = 1;

  /* ------------------------------------------------------------------ */
  /* Verbatim helpers from StorFuzz source — LLVM 11 compat fixes noted  */
  /* ------------------------------------------------------------------ */

  /*
   * Find a valid insertion point in the same basic block as `start`,
   * placing `insertionPoint` just after `start` (skipping PHIs / EH-pads).
   * PseudoProbeInst removed — not available in LLVM 11.
   */
  bool getInsertionPointInSameBB(Instruction          *start,
                                 BasicBlock::iterator &insertionPoint) {
    BasicBlock              *insertionBB = start->getParent();
    insertionPoint                       = start->getIterator();
    BasicBlock::const_iterator End       = insertionBB->end();
    int                        i         = 0;

    if (insertionPoint == End) { return false; }
    ++insertionPoint;

    while (insertionPoint != End && i < (int)insertionBB->size()) {
      if (!isa<PHINode>(*insertionPoint) && !insertionPoint->isEHPad()) {
        return true;
      } else if (insertionBB == &insertionBB->getParent()->getEntryBlock()) {
        /* Skip over static allocas and debug intrinsics at the entry */
        while (insertionPoint != End && i < (int)insertionBB->size() &&
               (isa<AllocaInst>(*insertionPoint) ||
                isa<DbgInfoIntrinsic>(*insertionPoint))) {
          if (const AllocaInst *AI = dyn_cast<AllocaInst>(&*insertionPoint)) {
            if (!AI->isStaticAlloca()) break;
          }
          i++;
        }
        return true;
      }
      ++insertionPoint;
      i++;
    }

    if (i >= (int)insertionBB->size()) {
      errs() << "ERROR: StorFuzzPass exceeded BB size. Start instr: " << *start
             << "\n";
      return false;
    }
    return insertionPoint != End;
  }

  /*
   * Returns true for functions that should never be instrumented.
   * List verbatim from StorFuzz source.
   * LLVM 11 fix: starts_with() → startswith().
   */
  bool isIgnoreFunction(const llvm::Function *F) {
    static constexpr const char *ignoreList[] = {
        "asan.",
        "llvm.",
        "sancov.",
        "__ubsan",
        "ign.",
        "__afl",
        "_fini",
        "__libc_",
        "__asan",
        "__msan",
        "__cmplog",
        "__sancov",
        "__san",
        "__cxx_",
        "__decide_deferred",
        "_GLOBAL",
        "_ZZN6__asan",
        "_ZZN6__lsan",
        "msan.",
        "LLVMFuzzerM",
        "LLVMFuzzerC",
        "LLVMFuzzerI",
        "maybe_duplicate_stderr",
        "discard_output",
        "close_stdout",
        "dup_and_close_stderr",
        "maybe_close_fd_mask",
        "ExecuteFilesOnyByOne",
    };

    for (auto const &f : ignoreList) {
      if (F->getName().startswith(f)) { return true; }
    }

    static constexpr const char *ignoreSubstringList[] = {
        "__asan",       "__msan",     "__ubsan", "__lsan",
        "__san",        "__sanitize", "__cxx",   "_GLOBAL__",
        "DebugCounter", "DwarfDebug", "DebugLoc"};

    for (auto const &f : ignoreSubstringList) {
      if (StringRef::npos != F->getName().find(f)) { return true; }
    }

    return false;
  }

  /* Verbatim from StorFuzz */
  static bool isSmallConstantAdditionOrSubtraction(Instruction *instr,
                                                   uint64_t smallConst = 2) {
    if (instr->getOpcode() == Instruction::Add) {
      for (auto op : instr->operand_values()) {
        if (isa<ConstantInt>(op) &&
            cast<ConstantInt>(op)->getValue().abs().ule(smallConst))
          return true;
      }
    } else if (instr->getOpcode() == Instruction::Sub) {
      if (isa<ConstantInt>(instr->getOperand(1)) &&
          cast<ConstantInt>(instr->getOperand(1))->getValue().abs().ule(
              smallConst))
        return true;
    }
    return false;
  }

  /* Verbatim from StorFuzz — strips cast chain */
  Value *uncast(Value *value) {
    CastInst *ci = nullptr;
    Value    *v  = value;
    while ((ci = dyn_cast<CastInst>(v)))
      v = ci->getOperand(0);
    return v;
  }

  /*
   * Returns true if potentialLoopCtr looks like a loop counter.
   * LoopInfo == nullptr → return false (loop-counter detection disabled;
   * conservative: may instrument some loop counters, which is acceptable).
   * Warning removed — would spam for every store in legacy-PM builds.
   */
  bool isLoopCtr(LoopInfo *loopInfo, Value *potentialLoopCtr,
                 Value *potentialLoopCtrLocation) {
    if (loopInfo == nullptr) { return false; }

    Value       *actualDef     = uncast(potentialLoopCtr);
    Instruction *actualDefInst = dyn_cast<Instruction>(actualDef);

    bool is_loop_ctr = false;
    if (actualDefInst &&
        isSmallConstantAdditionOrSubtraction(actualDefInst, 8)) {
      auto loop = loopInfo->getLoopFor(actualDefInst->getParent());
      while (loop && !is_loop_ctr) {
        /* getLatchCmpInst() not available in LLVM 11; LI is always null in
         * legacy-PM builds so this code is unreachable in practice. */
        CmpInst *cmp_instr = nullptr;
        if (cmp_instr) {
          for (auto val : cmp_instr->operand_values()) {
            if (val == actualDef || val == potentialLoopCtr ||
                val == potentialLoopCtrLocation) {
              is_loop_ctr = true;
            }
            if (isa<Instruction>(val)) {
              for (auto indirect_val :
                   cast<Instruction>(val)->operand_values()) {
                if (indirect_val == actualDef ||
                    indirect_val == potentialLoopCtr ||
                    indirect_val == potentialLoopCtrLocation) {
                  is_loop_ctr = true;
                  break;
                }
              }
            }
          }
        }
        loop = loop->getParentLoop();
      }
    }
    return is_loop_ctr;
  }
};

}  // namespace

char StorFuzzCoverage::ID = 1;

bool StorFuzzCoverage::runOnModule(Module &M) {
  /* Honor CONFIGURE_MODE used by some build systems */
  if (getenv("CONFIGURE_MODE")) { return true; }

  LLVMContext &C = M.getContext();

  IntegerType *Int8Ty  = IntegerType::getInt8Ty(C);
  IntegerType *Int16Ty = IntegerType::getInt16Ty(C);  /* used in reduction */
  IntegerType *Int32Ty = IntegerType::getInt32Ty(C);
  (void)Int16Ty; /* suppress unused warning — used via IRB.getInt16Ty() */

  /* Seed rand() once per module (matches StorFuzz behaviour) */
  srand((unsigned)time(NULL));

  /*
   * The map-pointer global.  ExternalLinkage (not weak) so the linker pulls
   * storfuzz_rt.o from libruntime_fast.a — weak references don't force archive
   * members.  The runtime provides the static fallback buffer when no shmem
   * env-var is set, so standalone binaries still work.
   *
   * Named __angora_data_area_ptr to follow Angora's ANGORA_* convention
   * (upstream StorFuzz calls it __storfuzz_area_ptr).
   */
  GlobalVariable *StorFuzzMapPtr = new GlobalVariable(
      M, PointerType::getUnqual(Int8Ty), /* isConstant */ false,
      GlobalValue::ExternalLinkage, /* Initializer */ nullptr,
      "__angora_data_area_ptr");

  /* Eight possible single-bit masks — chosen randomly per site at compile
   * time, verbatim from StorFuzz */
  ConstantInt *Mask[8] = {
      ConstantInt::get(Int8Ty, 1 << 0), ConstantInt::get(Int8Ty, 1 << 1),
      ConstantInt::get(Int8Ty, 1 << 2), ConstantInt::get(Int8Ty, 1 << 3),
      ConstantInt::get(Int8Ty, 1 << 4), ConstantInt::get(Int8Ty, 1 << 5),
      ConstantInt::get(Int8Ty, 1 << 6), ConstantInt::get(Int8Ty, 1 << 7)};

  /* MAX_STORES_PER_BB — read from env at pass run time, default 9 */
  int THRESHOLD = 0;
  if (const char *env_str = getenv("MAX_STORES_PER_BB"))
    THRESHOLD = atoi(env_str);
  if (THRESHOLD <= 0) THRESHOLD = 9;

  assert(isPowerOf2_32(map_size));

  /* VALUE_REDUCTION_WIDTH — read from env at pass run time, default 8 */
  int REDUCTION_WIDTH = 0;
  if (const char *env_str = getenv("VALUE_REDUCTION_WIDTH"))
    REDUCTION_WIDTH = atoi(env_str);
  if (REDUCTION_WIDTH <= 0) REDUCTION_WIDTH = 8;
  assert(map_size * 8 >= (uint32_t)(1 << REDUCTION_WIDTH) * 4096);

  int inst_stores = 0;

  for (auto &F : M) {
    /* Skip declarations, ignored functions, read-only functions, tiny ones */
    if (F.isDeclaration()) continue;
    if (isIgnoreFunction(&F)) continue;
    if (F.onlyReadsMemory()) continue;
    if (F.size() < function_minimum_size) continue;

    /*
     * LoopInfo: in Legacy PM without explicit analysis scheduling we cannot
     * reliably call getAnalysis<LoopInfoWrapperPass>(F) from a ModulePass.
     * Pass nullptr — isLoopCtr() returns false, disabling loop-counter
     * detection.  This is consistent with StorFuzz's own legacy-PM comment
     * ("without new pass manager, we do not support certain analyses").
     */
    LoopInfo *LI = nullptr;

    SmallDenseMap<BasicBlock *, uint16_t> stores_per_bb(8);

    /*
     * Two-pass loop — verbatim from StorFuzz:
     *   pass 0: count qualifying stores per BB (fills stores_per_bb)
     *   pass 1: emit IR for BBs below THRESHOLD
     */
    for (int pass = 0; pass < 2; pass++) {
      bool instrument_this_time = (pass == 1);

      if (instrument_this_time) {
        if (stores_per_bb.empty()) {
          errs() << "ERROR: StorFuzzPass: no BB info in '" << M.getName()
                 << ": " << F.getName() << "'\n";
          break;
        }
      }

      for (auto &BB : F) {
        BasicBlock::iterator insertionPoint = BB.getFirstInsertionPt();
        IRBuilder<>          IRB(&(*insertionPoint));
        uint16_t             BB_store_count = 0;

        if (instrument_this_time) {
          int stores_in_this_bb = 0;
          auto it = stores_per_bb.find(&BB);
          if (it != stores_per_bb.end()) {
            stores_in_this_bb = it->getSecond();
          } else {
            errs() << "ERROR: StorFuzzPass: BB not in map: " << M.getName()
                   << ": " << F.getName() << ": " << BB.getName() << "\n";
          }
          if (stores_in_this_bb == 0) continue;
          if (stores_in_this_bb > THRESHOLD) {
            dbgs() << "DEBUG: StorFuzzPass: skipping BB " << BB.getName()
                   << " (" << stores_in_this_bb << " > " << THRESHOLD
                   << " stores)\n";
            continue;
          }
        }

        for (auto &instr : BB) {
          StoreInst *storeInst = dyn_cast<StoreInst>(&instr);
          if (!storeInst) continue;

          /* Skip AFL/Angora instrumentation markers */
          if (storeInst->getMetadata("nosanitize") != nullptr) continue;

          Value *storeLocation = storeInst->getPointerOperand();

          /* Skip stores to alloca'd locations */
          if (dyn_cast<AllocaInst>(storeLocation)) continue;

          Value *storedValue = storeInst->getValueOperand();

          /* Skip if stored value does not come from an instruction */
          Instruction *valueDefInstruction = dyn_cast<Instruction>(storedValue);
          if (!valueDefInstruction) continue;

          /* Only instrument integer-typed stores */
          if (!dyn_cast<IntegerType>(storedValue->getType())) continue;

          /* Peel casts to find the original value */
          Value       *actual_storedValue        = uncast(storedValue);
          Instruction *actual_valueDefInstruction =
              dyn_cast<Instruction>(actual_storedValue);
          if (!actual_valueDefInstruction) continue;

          /*
           * Skip mem-to-mem copies (load→store, no transformation).
           * LLVM 11 fix: isa<LoadInst,VAArgInst>() → two separate isa<> calls.
           */
          if ((isa<LoadInst>(actual_valueDefInstruction) ||
               isa<VAArgInst>(actual_valueDefInstruction)) &&
              !getenv("STORFUZZ_INSTRUMENT_MEM2MEM_COPY")) {
            continue;
          }

          /* Skip loop counters */
          if (isLoopCtr(LI, storedValue, storeLocation)) continue;

          /* The original value type must also be integer */
          if (!dyn_cast<IntegerType>(actual_storedValue->getType())) continue;

          /* -------- count / instrument -------- */

          /* Per-site data (set during instrumentation pass) */
          Value    *CurLoc          = nullptr;
          uint32_t  bitmask_selector = 0;

          /*
           * Map from store-location values to compile-time random IDs.
           * Used to give distinct IDs to stores through different PHI
           * incoming values.
           */
          DenseMap<Value *, ConstantInt *> storeLocationToID(4);

          if (!instrument_this_time) {
            /* ---- pass 0: count ---- */
            if (isa<PHINode>(storeLocation)) {
              PHINode *phi = dyn_cast<PHINode>(storeLocation);
              for (uint32_t i = 0; i < phi->getNumIncomingValues(); i++) {
                if (storeLocationToID.find(phi->getIncomingValue(i)) ==
                    storeLocationToID.end()) {
                  storeLocationToID.insert({phi->getIncomingValue(i), nullptr});
                  BB_store_count++;
                }
              }
            } else {
              BB_store_count++;
            }
          } else {
            /* ---- pass 1: instrument ---- */

            if (isa<PHINode>(storeLocation)) {
              /* Stores through a PHI — create a CurLoc PHI node */
              PHINode *storeLocPhi = dyn_cast<PHINode>(storeLocation);

              insertionPoint = storeLocPhi->getIterator();
              while (insertionPoint != storeLocPhi->getParent()->end() &&
                     isa<PHINode>(*insertionPoint)) {
                ++insertionPoint;
              }
              assert(insertionPoint != storeLocPhi->getParent()->end());
              IRB.SetInsertPoint(storeLocPhi->getParent(), insertionPoint);

              PHINode *CurLocPhi =
                  IRB.CreatePHI(Int32Ty, storeLocPhi->getNumIncomingValues());

              for (uint32_t i = 0; i < storeLocPhi->getNumIncomingValues();
                   i++) {
                ConstantInt *curLocID;
                auto         it =
                    storeLocationToID.find(storeLocPhi->getIncomingValue(i));
                if (it == storeLocationToID.end()) {
                  curLocID =
                      ConstantInt::get(Int32Ty, RandBelow(map_size));
                  BB_store_count++;
                  storeLocationToID.insert(
                      {storeLocPhi->getIncomingValue(i), curLocID});
                } else {
                  curLocID = it->getSecond();
                }
                CurLocPhi->addIncoming(curLocID,
                                       storeLocPhi->getIncomingBlock(i));
              }
              CurLoc = CurLocPhi;

            } else {
              /* Non-PHI store location: assign a fresh random site ID */
              CurLoc = ConstantInt::get(Int32Ty, RandBelow(map_size));
              BB_store_count++;
            }

            bitmask_selector = RandBelow(8);

            /* Find insertion point: prefer just after value definition */
            if (isa<PHINode>(storeLocation) ||
                !getInsertionPointInSameBB(valueDefInstruction,
                                           insertionPoint)) {
              if (!isa<PHINode>(storeLocation)) {
                errs() << "WARNING: StorFuzzPass: no insertion point near "
                          "value def in '"
                       << F.getName() << "'\n";
              }
              if (!getInsertionPointInSameBB(storeInst, insertionPoint)) {
                errs() << "ERROR: StorFuzzPass: no insertion point in '"
                       << F.getName() << "'\n";
                assert(0);
              }
            }

            BasicBlock *insertionBB = insertionPoint->getParent();
            IRB.SetInsertPoint(insertionBB, insertionPoint);

            Value *mask = Mask[bitmask_selector];

            /* ---- Value reduction (verbatim from StorFuzz) ---- */
            Value *Lower16Bit =
                IRB.CreateZExtOrTrunc(storedValue, IRB.getInt16Ty());
            Value *ReducedValue = nullptr;

            if (REDUCTION_WIDTH == 8) {
              Value *Upper8Bit = IRB.CreateZExtOrTrunc(
                  IRB.CreateLShr(Lower16Bit, 8), IRB.getInt8Ty());
              Value *Lower8Bit =
                  IRB.CreateZExtOrTrunc(Lower16Bit, IRB.getInt8Ty());
              ReducedValue = IRB.CreateXor(Upper8Bit, Lower8Bit);

            } else if (REDUCTION_WIDTH == 4) {
              Value *Upper8Bit = IRB.CreateZExtOrTrunc(
                  IRB.CreateLShr(Lower16Bit, 8), IRB.getInt8Ty());
              Value *Lower8Bit =
                  IRB.CreateZExtOrTrunc(Lower16Bit, IRB.getInt8Ty());
              Value *half = IRB.CreateXor(Upper8Bit, Lower8Bit);
              ReducedValue =
                  IRB.CreateXor(IRB.CreateAnd(half, 0xF),
                                IRB.CreateLShr(half, 4));

            } else if (REDUCTION_WIDTH == 12) {
              auto tmp1 =
                  IRB.CreateLShr(IRB.CreateAnd(Lower16Bit, 0xFF00), 4);
              auto tmp2 = IRB.CreateAnd(Lower16Bit, 0xFF);
              ReducedValue =
                  IRB.CreateAnd(IRB.CreateXor(tmp1, tmp2), 0xFFF);

            } else if (REDUCTION_WIDTH == 16) {
              ReducedValue = Lower16Bit;

            } else {
              assert(false && "StorFuzzPass: unsupported REDUCTION_WIDTH");
            }

            /* ---- Load map pointer ----
             * LLVM 11 fix: CreateLoad(Value*) — no explicit element-type arg.
             */
            LoadInst *MapPtrLoad = IRB.CreateLoad(StorFuzzMapPtr);
            MapPtrLoad->setMetadata(M.getMDKindID("nosanitize"),
                                    MDNode::get(C, {}));

            /* ---- Map index: CurLoc XOR zext(ReducedValue, i32) ----
             * LLVM 11 fix: CreateGEP(Value*, ...) — no element-type arg.
             */
            Value *MapPtrIdx = IRB.CreateGEP(
                MapPtrLoad,
                IRB.CreateXor(CurLoc, IRB.CreateZExtOrTrunc(
                                          ReducedValue, IRB.getInt32Ty())));
            dyn_cast<Instruction>(MapPtrIdx)->setMetadata(
                M.getMDKindID("storfuzz_calc_index"), MDNode::get(C, {}));

            /* ---- map_ptr[idx] |= mask (AtomicRMW Or, Monotonic) ----
             * LLVM 11 fix: no MaybeAlign argument (added in LLVM 13).
             */
            IRB.CreateAtomicRMW(llvm::AtomicRMWInst::BinOp::Or, MapPtrIdx,
                                 mask, llvm::AtomicOrdering::Monotonic);

          }  /* instrument_this_time */
        }    /* instructions in BB */

        if (!instrument_this_time) {
          if (stores_per_bb.count(&BB)) {
            errs() << "ERROR: StorFuzzPass: BB already counted: "
                   << M.getName() << ": " << F.getName() << ": "
                   << BB.getName() << "\n";
          }
          stores_per_bb.insert({&BB, BB_store_count});
        } else {
          inst_stores += BB_store_count;
        }
      }  /* BBs */
    }    /* two-pass loop */
  }      /* functions */

  /* Verbose output — only when STORFUZZ_VERBOSE is set */
  if (getenv("STORFUZZ_VERBOSE")) {
    errs() << "StorFuzzPass: Instrumented " << inst_stores << " stores in '"
           << M.getName() << "'\n";
  }

  return true;
}

/* ---- Legacy PM registration — mirrors AngoraPass.cc exactly ---- */

static void registerStorFuzzPass(const PassManagerBuilder &,
                                 legacy::PassManagerBase  &PM) {
  PM.add(new StorFuzzCoverage());
}

static RegisterStandardPasses RegisterStorFuzzPass(
    PassManagerBuilder::EP_OptimizerLast, registerStorFuzzPass);

static RegisterStandardPasses RegisterStorFuzzPass0(
    PassManagerBuilder::EP_EnabledOnOptLevel0, registerStorFuzzPass);
