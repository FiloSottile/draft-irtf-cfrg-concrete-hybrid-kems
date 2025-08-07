//! Tests for nominal group implementations

#[cfg(test)]
mod tests {
    use crate::generic::test_utils::test_group_all;
    use crate::groups::{P256Group, P384Group, X25519Group};

    #[test]
    fn test_p256_group() {
        test_group_all::<P256Group>();
    }

    #[test]
    fn test_p384_group() {
        test_group_all::<P384Group>();
    }

    #[test]
    fn test_x25519_group() {
        test_group_all::<X25519Group>();
    }
}
