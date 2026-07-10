use angora_common::tag::TagSeg;

// Merges adjacent segments (current.end == next.begin) into one wider segment,
// e.g. [0..2, 2..4, 7..8] -> [0..4, 7..8]. Assumes offsets is sorted by begin.
pub fn merge_continuous_segments(offsets: &Vec<TagSeg>) -> Vec<TagSeg> {
    if offsets.is_empty() {
        return vec![];
    }

    let mut merged = Vec::new();
    let mut current = offsets[0];

    for i in 1..offsets.len() {
        let next = offsets[i];
        if current.end == next.begin {
            current.end = next.end;
        } else {
            merged.push(current);
            current = next;
        }
    }
    merged.push(current);
    merged
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merge_continuous_segments() {
        let v = vec![
            TagSeg {
                sign: false,
                begin: 0,
                end: 2,
            },
            TagSeg {
                sign: false,
                begin: 2,
                end: 4,
            },
            TagSeg {
                sign: false,
                begin: 7,
                end: 8,
            },
        ];
        let merged = merge_continuous_segments(&v);
        assert_eq!(merged.len(), 2);
        assert_eq!((merged[0].begin, merged[0].end), (0, 4));
        assert_eq!((merged[1].begin, merged[1].end), (7, 8));
    }
}
