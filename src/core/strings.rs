//! Utilities for dealing with strings.

/// Capitalize the first letter of a string.
#[must_use]
pub fn title_case(s: &str) -> String {
    let words: Vec<&str> = s.split_whitespace().collect();
    let mut result = String::new();
    for word in words {
        let mut chars = word.chars();
        match chars.next() {
            None => continue,
            Some(c) => {
                let capitalized = c.to_uppercase().collect::<String>() + chars.as_str();
                result.push_str(&capitalized);
            }
        }
        result.push(' ');
    }
    result.trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_title_case() {
        assert_eq!(title_case("hello, world!"), "Hello, World!");
        assert_eq!(title_case("hello world"), "Hello World");
        assert_eq!(title_case("hello"), "Hello");
        assert_eq!(title_case("hello, World"), "Hello, World");
        assert_eq!(title_case("hello, world!"), "Hello, World!");
    }
}
