use sentinel_core::{LanguageAdapter, ParseError, UniversalAST};

#[derive(Debug, Default)]
pub struct ClarityAdapter;

impl LanguageAdapter for ClarityAdapter {
    fn parse(&self, source: &str) -> Result<UniversalAST, ParseError> {
        parse_clarity(source)
    }
}

pub fn parse_clarity(source: &str) -> Result<UniversalAST, ParseError> {
    if source.trim().is_empty() {
        return Err(ParseError::InvalidSource("empty Clarity source".to_string()));
    }

    Ok(UniversalAST::new("inline.clar"))
}
