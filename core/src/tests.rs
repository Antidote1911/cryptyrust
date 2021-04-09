pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

// This is a really bad adding function, its purpose is to fail in this
// example.
#[allow(dead_code)]
fn mul(a: i32, b: i32) -> i32 {
    a * b
}

#[cfg(test)]
mod tests {
    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(1, 2), 3);
    }

    #[test]
    fn test_mul() {
        // This assert would fire and test will fail.
        // Please note, that private functions can be tested too!
        assert_eq!(mul(2, 3), 6);
    }
}
