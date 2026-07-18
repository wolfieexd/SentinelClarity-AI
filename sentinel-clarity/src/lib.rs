use sentinel_core::{
    Annotation, CallTarget, Expr, Function, LanguageAdapter, Param, ParseError, Span, Stmt,
    StorageOp, UniversalAST, UniversalNode, Visibility,
};

#[derive(Debug, Default)]
pub struct ClarityAdapter;

impl LanguageAdapter for ClarityAdapter {
    fn parse(&self, source: &str) -> Result<UniversalAST, ParseError> {
        parse_clarity(source)
    }
}

pub fn parse_clarity(source: &str) -> Result<UniversalAST, ParseError> {
    if source.trim().is_empty() {
        return Err(ParseError::InvalidSource(
            "empty Clarity source".to_string(),
        ));
    }
    validate_source_syntax(source)?;

    let functions = extract_functions(source);
    let traits = extract_trait_names(source);
    let mut ast = UniversalAST::with_source("inline.clar", source);

    ast.nodes.push(UniversalNode::Contract {
        name: "contract".to_string(),
        traits,
        functions,
    });

    Ok(ast)
}

fn extract_functions(source: &str) -> Vec<Function> {
    let lines: Vec<&str> = source.lines().collect();
    let sanitized_source = sanitize_clarity_code(source);
    let sanitized_lines: Vec<&str> = sanitized_source.lines().collect();
    let mut functions = Vec::new();
    let mut line_index = 0;

    while line_index < lines.len() {
        let line = sanitized_lines[line_index].trim();
        let visibility = if line.contains("(define-public") {
            Some(Visibility::Public)
        } else if line.contains("(define-private") {
            Some(Visibility::Private)
        } else if line.contains("(define-read-only") {
            Some(Visibility::ReadOnly)
        } else {
            None
        };

        if let Some(visibility) = visibility {
            let start = line_index;
            let mut end = line_index;
            let mut balance = paren_delta(sanitized_lines[line_index]);

            while balance > 0 && end + 1 < lines.len() {
                end += 1;
                balance += paren_delta(sanitized_lines[end]);
            }

            let body = lines[start..=end].join("\n");
            let name = extract_function_name(&body).unwrap_or_else(|| "anonymous".to_string());
            let span = Span {
                start_line: (start + 1) as u32,
                start_col: 1,
                end_line: (end + 1) as u32,
                end_col: lines[end].len().max(1) as u32,
            };

            functions.push(Function {
                name,
                visibility,
                params: extract_params(&body),
                body: extract_statements(&body),
                annotations: extract_annotations(&body, span),
                span,
            });

            line_index = end;
        }

        line_index += 1;
    }

    functions
}

fn paren_delta(line: &str) -> i32 {
    line.chars().fold(0, |balance, ch| match ch {
        '(' => balance + 1,
        ')' => balance - 1,
        _ => balance,
    })
}

fn extract_function_name(body: &str) -> Option<String> {
    let marker = "(define-";
    let start = body.find(marker)?;
    let after_define = &body[start + marker.len()..];
    let open_name = after_define.find('(')?;
    let name_text = after_define[open_name + 1..]
        .split_whitespace()
        .next()?
        .trim_matches(')')
        .to_string();

    Some(name_text)
}

fn extract_params(body: &str) -> Vec<Param> {
    let Some(name) = extract_function_name(body) else {
        return Vec::new();
    };
    let Some(signature_start) = body.find(&format!("({name}")) else {
        return Vec::new();
    };
    let signature = &body[signature_start + name.len() + 1..];
    signature
        .split(')')
        .next()
        .unwrap_or_default()
        .split('(')
        .skip(1)
        .filter_map(|param| {
            let mut parts = param.split_whitespace();
            let name = parts.next()?.to_string();
            let ty = parts.next().unwrap_or("unknown").to_string();
            Some(Param { name, ty })
        })
        .collect()
}

fn extract_statements(body: &str) -> Vec<Stmt> {
    let mut statements = Vec::new();
    let code = sanitize_clarity_code(body);

    for (needle, op) in [
        ("map-set", StorageOp::MapSet("unknown".to_string())),
        ("var-set", StorageOp::VarSet("unknown".to_string())),
        ("stx-transfer?", StorageOp::Transfer),
        ("contract-call?", StorageOp::ContractCall),
    ] {
        if code.contains(needle) {
            statements.push(Stmt::StateChange(op));
        }
    }

    if code.contains("contract-call?") {
        statements.push(Stmt::Expr(Expr::Call {
            target: CallTarget::External {
                contract: "unknown".to_string(),
                function: "unknown".to_string(),
            },
            args: Vec::new(),
            checked: code.contains("try!") || code.contains("match"),
        }));
    }

    statements.push(Stmt::Expr(Expr::Literal(code)));
    statements
}

fn extract_annotations(body: &str, span: Span) -> Vec<Annotation> {
    if body.contains("#[read_only]") {
        vec![Annotation {
            name: "read_only".to_string(),
            args: Vec::new(),
            span,
        }]
    } else {
        Vec::new()
    }
}

fn extract_trait_names(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.starts_with("(impl-trait") || trimmed.starts_with("(define-trait") {
                trimmed
                    .split_whitespace()
                    .nth(1)
                    .map(|name| name.trim_matches(')').to_string())
            } else {
                None
            }
        })
        .collect()
}

fn validate_source_syntax(source: &str) -> Result<(), ParseError> {
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;
    let mut in_comment = false;

    for (index, character) in source.char_indices() {
        if in_comment {
            if character == '\n' {
                in_comment = false;
            }
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            continue;
        }
        if source[index..].starts_with(";;") {
            in_comment = true;
            continue;
        }
        match character {
            '"' => in_string = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth < 0 {
                    return Err(ParseError::InvalidSource(format!(
                        "unexpected closing parenthesis near byte {index}"
                    )));
                }
            }
            _ => {}
        }
    }

    if in_string {
        return Err(ParseError::InvalidSource(
            "unterminated string literal".to_string(),
        ));
    }
    if depth != 0 {
        return Err(ParseError::InvalidSource(
            "unbalanced parentheses".to_string(),
        ));
    }
    Ok(())
}

fn sanitize_clarity_code(source: &str) -> String {
    let mut sanitized = String::with_capacity(source.len());
    let mut in_string = false;
    let mut escaped = false;
    let mut in_comment = false;
    let characters = source.chars().collect::<Vec<_>>();
    let mut index = 0;

    while index < characters.len() {
        let character = characters[index];
        if in_comment {
            if character == '\n' {
                in_comment = false;
                sanitized.push('\n');
            } else {
                sanitized.push(' ');
            }
            index += 1;
            continue;
        }
        if in_string {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                in_string = false;
            }
            sanitized.push(if character == '\n' { '\n' } else { ' ' });
            index += 1;
            continue;
        }
        if character == ';' && characters.get(index + 1) == Some(&';') {
            in_comment = true;
            sanitized.push(' ');
            sanitized.push(' ');
            index += 2;
            continue;
        }
        if character == '"' {
            in_string = true;
            sanitized.push(' ');
        } else {
            sanitized.push(character);
        }
        index += 1;
    }

    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_core::LanguageAdapter;

    #[test]
    fn malformed_source_is_rejected_before_scanning() {
        assert!(ClarityAdapter
            .parse("(define-public (broken) (ok true)")
            .is_err());
        assert!(ClarityAdapter
            .parse("(define-public (broken) \"unterminated)")
            .is_err());
    }

    #[test]
    fn comments_and_strings_do_not_create_security_findings() {
        let source = r#"
            ;; (define-public (set-owner) (var-set owner tx-sender))
            (define-read-only (message) "contract-call? map-set var-set")
        "#;
        let ast = ClarityAdapter.parse(source).expect("source parses");
        let function = ast.functions().pop().expect("function is extracted");
        let body = function
            .body
            .iter()
            .find_map(|statement| match statement {
                Stmt::Expr(Expr::Literal(body)) => Some(body.as_str()),
                _ => None,
            })
            .expect("function body is present");

        assert!(!body.contains("contract-call?"));
        assert!(!body.contains("map-set"));
        assert!(!body.contains("var-set"));
    }
}
