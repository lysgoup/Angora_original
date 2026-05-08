extern crate cc;

fn main() {
    cc::Build::new()
        .file("src/context.c")
        .file("src/storfuzz_rt.c")
        .compile("libcontext.a");
}
