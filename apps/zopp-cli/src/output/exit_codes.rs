pub const SUCCESS: i32 = 0;
pub const PARTIAL_FAILURE: i32 = 1;
pub const TOTAL_FAILURE: i32 = 2;
pub const CONFIG_ERROR: i32 = 3;
pub const CONNECTION_ERROR: i32 = 4;

/// Determine the exit code based on total and failed counts.
pub fn from_results(total: usize, failed: usize) -> i32 {
    if failed == 0 {
        SUCCESS
    } else if failed == total {
        TOTAL_FAILURE
    } else {
        PARTIAL_FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_succeeded() {
        assert_eq!(from_results(3, 0), SUCCESS);
    }

    #[test]
    fn test_all_failed() {
        assert_eq!(from_results(3, 3), TOTAL_FAILURE);
    }

    #[test]
    fn test_partial_failure() {
        assert_eq!(from_results(3, 1), PARTIAL_FAILURE);
    }

    #[test]
    fn test_no_results() {
        assert_eq!(from_results(0, 0), SUCCESS);
    }

    #[test]
    fn test_constants() {
        assert_eq!(SUCCESS, 0);
        assert_eq!(PARTIAL_FAILURE, 1);
        assert_eq!(TOTAL_FAILURE, 2);
        assert_eq!(CONFIG_ERROR, 3);
        assert_eq!(CONNECTION_ERROR, 4);
    }
}
