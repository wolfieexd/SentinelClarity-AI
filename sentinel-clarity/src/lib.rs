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
    let mut functions = Vec::new();
    let mut line_index = 0;

    while line_index < lines.len() {
        let line = lines[line_index].trim();
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
            let mut balance = paren_delta(lines[line_index]);

            while balance > 0 && end + 1 < lines.len() {
                end += 1;
                balance += paren_delta(lines[end]);
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

    for (needle, op) in [
        ("map-set", StorageOp::MapSet("unknown".to_string())),
        ("var-set", StorageOp::VarSet("unknown".to_string())),
        ("stx-transfer?", StorageOp::Transfer),
        ("contract-call?", StorageOp::ContractCall),
    ] {
        if body.contains(needle) {
            statements.push(Stmt::StateChange(op));
        }
    }

    if body.contains("contract-call?") {
        statements.push(Stmt::Expr(Expr::Call {
            target: CallTarget::External {
                contract: "unknown".to_string(),
                function: "unknown".to_string(),
            },
            args: Vec::new(),
            checked: body.contains("try!") || body.contains("match"),
        }));
    }

    statements.push(Stmt::Expr(Expr::Literal(body.to_string())));
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
