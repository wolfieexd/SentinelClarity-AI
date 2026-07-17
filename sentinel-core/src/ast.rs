use serde::{Deserialize, Serialize};

pub type FileId = String;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UniversalAST {
    pub file_id: FileId,
    pub nodes: Vec<UniversalNode>,
}

impl UniversalAST {
    pub fn new(file_id: impl Into<FileId>) -> Self {
        Self {
            file_id: file_id.into(),
            nodes: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UniversalNode {
    Contract {
        name: String,
        traits: Vec<String>,
        functions: Vec<Function>,
    },
    Function(Function),
    Call {
        target: CallTarget,
        args: Vec<Expr>,
        checked: bool,
        span: Span,
    },
    StateChange {
        storage: StorageOp,
        location: Span,
    },
    Annotation {
        name: String,
        args: Vec<Expr>,
        span: Span,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Function {
    pub name: String,
    pub visibility: Visibility,
    pub params: Vec<Param>,
    pub body: Vec<Stmt>,
    pub annotations: Vec<Annotation>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub ty: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Annotation {
    pub name: String,
    pub args: Vec<Expr>,
    pub span: Span,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Visibility {
    Public,
    Private,
    ReadOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Stmt {
    Expr(Expr),
    StateChange(StorageOp),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Expr {
    Symbol(String),
    Literal(String),
    Call {
        target: CallTarget,
        args: Vec<Expr>,
        checked: bool,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallTarget {
    Local(String),
    External { contract: String, function: String },
    Trait(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageOp {
    MapSet(String),
    VarSet(String),
    Transfer,
    ContractCall,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Span {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

impl Default for Span {
    fn default() -> Self {
        Self {
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 1,
        }
    }
}
