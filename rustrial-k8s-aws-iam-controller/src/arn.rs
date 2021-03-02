use std::convert::TryFrom;

pub struct ARN<'a> {
    pub prefix: &'a str,
    pub partition: &'a str,
    pub service: &'a str,
    pub region: &'a str,
    pub account: &'a str,
    pub typ: &'a str,
    pub suffix: &'a str,
}

impl<'a> ARN<'a> {
    pub fn matches<'b>(&self, rhs: &ARN<'b>) -> bool {
        fn joker_match(a: &str, b: &str) -> bool {
            a == b || a == "*"
        }
        fn prefix_match(a: &str, b: &str) -> bool {
            a.ends_with("*") && b.starts_with(&a[0..a.len() - 1])
        }
        self.prefix == rhs.prefix
            && joker_match(self.partition, rhs.partition)
            && self.service == rhs.service
            && joker_match(self.region, rhs.region)
            && joker_match(self.account, rhs.account)
            && self.typ == rhs.typ
            && (joker_match(self.suffix, rhs.suffix)
                || prefix_match(self.suffix, rhs.suffix)
                || prefix_match(rhs.suffix, self.suffix))
    }
}

impl<'a> TryFrom<&'a str> for ARN<'a> {
    type Error = ();

    fn try_from(arn: &'a str) -> Result<Self, Self::Error> {
        let r: Vec<&'a str> = arn.splitn(2, "/").collect();
        if let [prefix, suffix] = r.as_slice() {
            let p: Vec<&'a str> = prefix.split(":").collect();
            if let [prefix, partition, service, region, account, typ] = p.as_slice() {
                Ok(ARN {
                    prefix,
                    partition,
                    service,
                    region,
                    account,
                    typ,
                    suffix,
                })
            } else {
                Err(())
            }
        } else {
            Err(())
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn parse() -> anyhow::Result<()> {
        assert!(ARN::try_from("arn:aws:iam::000000000000:role/path/name").is_ok());
        Ok(())
    }

    #[test]
    fn matches_full_arn() -> anyhow::Result<()> {
        let txt = "arn:aws:iam::000000000000:role/path/name";
        let pattern = ARN::try_from(txt).unwrap();
        let arn = ARN::try_from(txt).unwrap();
        assert!(pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn matches_any_account() -> anyhow::Result<()> {
        let pattern = ARN::try_from("arn:aws:iam::*:role/path/name").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert!(pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn matches_any_region() -> anyhow::Result<()> {
        let pattern = ARN::try_from("arn:aws:iam:*:000000000000:role/path/name").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert!(pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn matches_any_partition() -> anyhow::Result<()> {
        let pattern = ARN::try_from("arn:*:iam::000000000000:role/path/name").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert!(pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn matches_any_suffix() -> anyhow::Result<()> {
        let pattern = ARN::try_from("arn:aws:iam::000000000000:role/path/*").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert!(pattern.matches(&arn));
        let pattern = ARN::try_from("arn:aws:iam::000000000000:role/*").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert!(pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn rejects_different_prefix() -> anyhow::Result<()> {
        let pattern = ARN::try_from("xxx:aws:iam::000000000000:role/path/name").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert_eq!(false, pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn rejects_different_partition() -> anyhow::Result<()> {
        let pattern = ARN::try_from("arn:xxx:iam::000000000000:role/path/name").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert_eq!(false, pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn rejects_different_service() -> anyhow::Result<()> {
        let pattern = ARN::try_from("arn:aws:sts::000000000000:role/path/name").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert_eq!(false, pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn rejects_different_region() -> anyhow::Result<()> {
        let pattern = ARN::try_from("arn:aws:iam:xx:000000000000:role/path/name").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert_eq!(false, pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn rejects_different_account() -> anyhow::Result<()> {
        let pattern = ARN::try_from("arn:aws:iam::000000000001:role/path/name").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert_eq!(false, pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn rejects_different_type() -> anyhow::Result<()> {
        let pattern = ARN::try_from("arn:aws:iam::000000000000:user/path/name").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        assert_eq!(false, pattern.matches(&arn));
        Ok(())
    }

    #[test]
    fn rejects_different_suffix() -> anyhow::Result<()> {
        let pattern = ARN::try_from("arn:aws:iam::000000000000:role/path/name").unwrap();
        let arn = ARN::try_from("arn:aws:iam::000000000000:role/path/namex").unwrap();
        assert_eq!(false, pattern.matches(&arn));
        Ok(())
    }
}
