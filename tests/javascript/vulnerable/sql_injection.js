function findUser(req, db) {
  const sql = "SELECT * FROM users WHERE id = " + req.query.id;
  db.query(sql);
}

function findByName(req, db) {
  const sql = `SELECT * FROM users WHERE name = '${req.body.name}'`;
  db.execute(sql);
}
