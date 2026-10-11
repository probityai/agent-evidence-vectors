//! Typed shape checks: a subject whose members have the wrong JSON types is
//! not an instance of its definition, and no row is read off it. Each check
//! below only asks for the JSON type a definition gives a member; anything a
//! row reads (a value outside a vocabulary, a count that disagrees, a missing
//! qualifier argument) is left to the row.

use serde_json::Value;

/// Collects one message per type error, with a path like `checks[1].cause`.
#[derive(Default)]
pub struct Shape {
    pub errors: Vec<String>,
}

#[derive(Clone, Copy)]
pub enum Ty {
    Object,
    Array,
    Str,
    Int,
    Bool,
    /// An object or JSON null.
    ObjectOrNull,
    /// A string or JSON null.
    StrOrNull,
}

fn is(v: &Value, ty: Ty) -> bool {
    match ty {
        Ty::Object => v.is_object(),
        Ty::Array => v.is_array(),
        Ty::Str => v.is_string(),
        Ty::Int => v
            .as_number()
            .is_some_and(|n| !crate::json::is_float_token(n)),
        Ty::Bool => v.is_boolean(),
        Ty::ObjectOrNull => v.is_object() || v.is_null(),
        Ty::StrOrNull => v.is_string() || v.is_null(),
    }
}

fn name(ty: Ty) -> &'static str {
    match ty {
        Ty::Object => "an object",
        Ty::Array => "an array",
        Ty::Str => "a string",
        Ty::Int => "an integer",
        Ty::Bool => "a boolean",
        Ty::ObjectOrNull => "an object or null",
        Ty::StrOrNull => "a string or null",
    }
}

impl Shape {
    /// `parent.key` must be present with type `ty`.
    pub fn need(&mut self, parent: &Value, path: &str, key: &str, ty: Ty) {
        match parent.get(key) {
            None => self
                .errors
                .push(format!("{} carries no {key} member", show(path))),
            Some(v) if !is(v, ty) => {
                self.errors
                    .push(format!("{}{key} is not {}", prefix(path), name(ty)))
            }
            Some(_) => {}
        }
    }

    /// `parent.key`, when present, must have type `ty`.
    pub fn may(&mut self, parent: &Value, path: &str, key: &str, ty: Ty) {
        if let Some(v) = parent.get(key) {
            if !is(v, ty) {
                self.errors
                    .push(format!("{}{key} is not {}", prefix(path), name(ty)));
            }
        }
    }

    /// Every element of the array at `parent.key` (when it is one) must have type `ty`.
    pub fn each(&mut self, parent: &Value, path: &str, key: &str, ty: Ty) {
        if let Some(items) = parent.get(key).and_then(Value::as_array) {
            for (i, v) in items.iter().enumerate() {
                if !is(v, ty) {
                    self.errors
                        .push(format!("{}{key}[{i}] is not {}", prefix(path), name(ty)));
                }
            }
        }
    }

    pub fn finish(self) -> Result<(), Vec<String>> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self.errors)
        }
    }
}

fn show(path: &str) -> String {
    if path.is_empty() {
        "the subject".into()
    } else {
        path.to_string()
    }
}

fn prefix(path: &str) -> String {
    if path.is_empty() {
        String::new()
    } else {
        format!("{path}.")
    }
}
