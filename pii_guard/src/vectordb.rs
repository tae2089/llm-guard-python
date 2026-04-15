pub struct SearchMatch {
    pub category: String,
    pub original_text: String,
    pub score: f32,
}

pub struct VectorDb;

impl VectorDb {
    pub fn open(_path: &str) -> Result<Self, String> {
        Ok(Self)
    }

    pub fn insert(&self, _category: &str, _text: &str, _embedding: &[f32]) -> Result<(), String> {
        Ok(())
    }

    pub fn search(&self, _embedding: &[f32], _threshold: f32) -> Result<Option<SearchMatch>, String> {
        Ok(None)
    }
}
