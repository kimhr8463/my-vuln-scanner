function findUser(req, db) {
  db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);
}

function findByName(req, db) {
  db.execute("SELECT * FROM users WHERE name = $1", [req.body.name]);
}

function fixedQuery(db) {
  db.query("SELECT * FROM users WHERE active = 1");
}
