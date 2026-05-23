use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyString};

#[derive(Clone, Debug)]
enum RuleExpr {
    Name(String),
    Not(Box<RuleExpr>),
    And(Box<RuleExpr>, Box<RuleExpr>),
    Or(Box<RuleExpr>, Box<RuleExpr>),
}

#[derive(Clone, Debug, PartialEq)]
enum Token {
    Name(String),
    Not,
    And,
    Or,
    LParen,
    RParen,
}
#[pyfunction]
pub(crate) fn parse_filter_rule_fast(py: Python<'_>, expression: &str) -> PyResult<PyObject> {
    let tokens = tokenize_rule(expression)?;
    let mut parser = RuleParserState::new(tokens);
    let expr = parser.parse_expression()?;
    if parser.has_remaining() {
        return Err(PyValueError::new_err("规则表达式包含无法解析的剩余内容"));
    }
    let outer = PyList::empty(py);
    outer.append(expr_to_py(py, &expr)?)?;
    Ok(outer.into())
}

/// 将规则字符串切分为名称、逻辑符和括号。
fn tokenize_rule(expression: &str) -> PyResult<Vec<Token>> {
    let chars: Vec<char> = expression.chars().collect();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < chars.len() {
        let ch = chars[index];
        if ch.is_whitespace() {
            index += 1;
            continue;
        }
        match ch {
            '!' => {
                tokens.push(Token::Not);
                index += 1;
            }
            '&' => {
                tokens.push(Token::And);
                index += 1;
            }
            '|' => {
                tokens.push(Token::Or);
                index += 1;
            }
            '(' => {
                tokens.push(Token::LParen);
                index += 1;
            }
            ')' => {
                tokens.push(Token::RParen);
                index += 1;
            }
            _ => {
                let start = index;
                while index < chars.len() && chars[index].is_ascii_alphanumeric() {
                    index += 1;
                }
                if start == index {
                    return Err(PyValueError::new_err(format!("非法规则字符: {ch}")));
                }
                let name: String = chars[start..index].iter().collect();
                if !is_valid_rule_name(&name) {
                    return Err(PyValueError::new_err(format!("非法规则名称: {name}")));
                }
                tokens.push(Token::Name(name));
            }
        }
    }
    if tokens.is_empty() {
        return Err(PyValueError::new_err("规则表达式不能为空"));
    }
    Ok(tokens)
}

/// 判断规则名称是否符合原 pyparsing 语法。
fn is_valid_rule_name(name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if first.is_ascii_alphabetic() {
        return chars.all(|ch| ch.is_ascii_alphanumeric());
    }
    if first.is_ascii_digit() {
        let mut seen_alpha = false;
        for ch in name.chars().skip_while(|ch| ch.is_ascii_digit()) {
            if !ch.is_ascii_alphanumeric() {
                return false;
            }
            if ch.is_ascii_alphabetic() {
                seen_alpha = true;
            }
        }
        return seen_alpha;
    }
    false
}

struct RuleParserState {
    tokens: Vec<Token>,
    index: usize,
}

impl RuleParserState {
    /// 创建规则解析器状态。
    fn new(tokens: Vec<Token>) -> Self {
        Self { tokens, index: 0 }
    }

    /// 解析完整表达式。
    fn parse_expression(&mut self) -> PyResult<RuleExpr> {
        self.parse_or()
    }

    /// 返回是否还有未消费 token。
    fn has_remaining(&self) -> bool {
        self.index < self.tokens.len()
    }

    /// 解析 or 表达式。
    fn parse_or(&mut self) -> PyResult<RuleExpr> {
        let mut expr = self.parse_and()?;
        while self.consume(&Token::Or) {
            let right = self.parse_and()?;
            expr = RuleExpr::Or(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    /// 解析 and 表达式。
    fn parse_and(&mut self) -> PyResult<RuleExpr> {
        let mut expr = self.parse_not()?;
        while self.consume(&Token::And) {
            let right = self.parse_not()?;
            expr = RuleExpr::And(Box::new(expr), Box::new(right));
        }
        Ok(expr)
    }

    /// 解析 not 表达式。
    fn parse_not(&mut self) -> PyResult<RuleExpr> {
        if self.consume(&Token::Not) {
            return Ok(RuleExpr::Not(Box::new(self.parse_not()?)));
        }
        self.parse_primary()
    }

    /// 解析原子或括号表达式。
    fn parse_primary(&mut self) -> PyResult<RuleExpr> {
        let Some(token) = self.tokens.get(self.index).cloned() else {
            return Err(PyValueError::new_err("规则表达式意外结束"));
        };
        match token {
            Token::Name(name) => {
                self.index += 1;
                Ok(RuleExpr::Name(name))
            }
            Token::LParen => {
                self.index += 1;
                let expr = self.parse_expression()?;
                if !self.consume(&Token::RParen) {
                    return Err(PyValueError::new_err("规则表达式缺少右括号"));
                }
                Ok(expr)
            }
            _ => Err(PyValueError::new_err("规则表达式缺少规则名称")),
        }
    }

    /// 如果下一个 token 匹配则消费它。
    fn consume(&mut self, token: &Token) -> bool {
        if self.tokens.get(self.index) == Some(token) {
            self.index += 1;
            return true;
        }
        false
    }
}

/// 将规则 AST 转换为 Python 兼容嵌套列表。
fn expr_to_py(py: Python<'_>, expr: &RuleExpr) -> PyResult<PyObject> {
    match expr {
        RuleExpr::Name(name) => Ok(PyString::new(py, name).into_any().unbind()),
        RuleExpr::Not(inner) => {
            let list = PyList::empty(py);
            list.append("not")?;
            list.append(expr_to_py(py, inner)?)?;
            Ok(list.into())
        }
        RuleExpr::And(left, right) => expr_binary_to_py(py, "and", left, right),
        RuleExpr::Or(left, right) => expr_binary_to_py(py, "or", left, right),
    }
}

/// 将二元规则 AST 转换为 Python 兼容嵌套列表。
fn expr_binary_to_py(
    py: Python<'_>,
    operator: &str,
    left: &RuleExpr,
    right: &RuleExpr,
) -> PyResult<PyObject> {
    let list = PyList::empty(py);
    list.append(expr_to_py(py, left)?)?;
    list.append(operator)?;
    list.append(expr_to_py(py, right)?)?;
    Ok(list.into())
}
