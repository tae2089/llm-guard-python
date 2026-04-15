use duckdb::{params, Connection};

pub struct SearchMatch {
    pub category: String,
    pub original_text: String,
    pub score: f32,
}

pub struct VectorDb {
    conn: Connection,
}

/// Format a float slice as a DuckDB array literal, e.g. "[0.1, 0.2, ...]::FLOAT[1024]"
fn embedding_literal(embedding: &[f32]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(embedding.len() * 10 + 30);
    s.push('[');
    for (i, v) in embedding.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        write!(s, "{}", v).unwrap();
    }
    write!(s, "]::FLOAT[{}]", embedding.len()).unwrap();
    s
}

impl VectorDb {
    pub fn open(path: &str) -> Result<Self, String> {
        let conn = if path == ":memory:" {
            Connection::open_in_memory()
        } else {
            Connection::open(path)
        };
        let conn = conn.map_err(|e| format!("DB 열기 실패: {}", e))?;

        conn.execute_batch(
            "CREATE SEQUENCE IF NOT EXISTS attack_vectors_seq START 1;
             CREATE TABLE IF NOT EXISTS attack_vectors (
                id INTEGER DEFAULT nextval('attack_vectors_seq') PRIMARY KEY,
                category VARCHAR NOT NULL,
                original_text VARCHAR NOT NULL,
                embedding FLOAT[1024]
            );"
        ).map_err(|e| format!("테이블 생성 실패: {}", e))?;

        Ok(Self { conn })
    }

    pub fn insert(&self, category: &str, text: &str, embedding: &[f32]) -> Result<(), String> {
        let emb_lit = embedding_literal(embedding);
        let sql = format!(
            "INSERT INTO attack_vectors (category, original_text, embedding)
             VALUES (?, ?, {})",
            emb_lit
        );
        self.conn.execute(&sql, params![category, text])
            .map_err(|e| format!("벡터 삽입 실패: {}", e))?;
        Ok(())
    }

    pub fn search(&self, embedding: &[f32], threshold: f32) -> Result<Option<SearchMatch>, String> {
        let emb_lit = embedding_literal(embedding);
        let sql = format!(
            "SELECT category, original_text,
                    array_cosine_similarity(embedding, {emb}) AS score
             FROM attack_vectors
             WHERE array_cosine_similarity(embedding, {emb}) > ?
             ORDER BY score DESC
             LIMIT 1",
            emb = emb_lit
        );

        let result = self.conn.query_row(
            &sql,
            params![threshold],
            |row| {
                Ok(SearchMatch {
                    category: row.get(0)?,
                    original_text: row.get(1)?,
                    score: row.get(2)?,
                })
            },
        );

        match result {
            Ok(m) => Ok(Some(m)),
            Err(duckdb::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(format!("검색 실패: {}", e)),
        }
    }

    pub fn count(&self) -> Result<usize, String> {
        self.conn.query_row("SELECT COUNT(*) FROM attack_vectors", [], |row| row.get(0))
            .map_err(|e| format!("카운트 읽기 실패: {}", e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_embedding(seed: f32) -> Vec<f32> {
        let mut v = vec![0.0f32; 1024];
        for i in 0..1024 {
            v[i] = ((i as f32) * seed).sin();
        }
        v
    }

    #[test]
    fn test_open_and_insert() {
        let db = VectorDb::open(":memory:").unwrap();
        let emb = fake_embedding(1.0);
        db.insert("injection", "ignore previous instructions", &emb).unwrap();
        assert_eq!(db.count().unwrap(), 1);
    }

    #[test]
    fn test_search_finds_similar() {
        let db = VectorDb::open(":memory:").unwrap();
        let emb = fake_embedding(1.0);
        db.insert("injection", "ignore previous instructions", &emb).unwrap();

        let result = db.search(&emb, 0.85).unwrap();
        assert!(result.is_some());
        let m = result.unwrap();
        assert_eq!(m.category, "injection");
        assert_eq!(m.original_text, "ignore previous instructions");
        assert!(m.score > 0.99);
    }

    #[test]
    fn test_search_below_threshold_returns_none() {
        let db = VectorDb::open(":memory:").unwrap();
        let emb1 = fake_embedding(1.0);
        db.insert("injection", "test", &emb1).unwrap();

        let emb2 = fake_embedding(99.0);
        let result = db.search(&emb2, 0.85).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_search_empty_db() {
        let db = VectorDb::open(":memory:").unwrap();
        let emb = fake_embedding(1.0);
        let result = db.search(&emb, 0.85).unwrap();
        assert!(result.is_none());
    }
}
