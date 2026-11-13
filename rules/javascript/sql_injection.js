const pg = require("pg");
const mysql = require("mysql2");
const makeKnex = require("knex");
const {Sequelize} = require("sequelize");

function pgConcatenation(req) {
  const pool = new pg.Pool();
  const sql = "SELECT * FROM users WHERE id = " + req.query.id;
  // ruleid: javascript-sql-injection-taint
  return pool.query(sql);
}

function mysqlTemplate(req) {
  const connection = mysql.createConnection({});
  const sql = `SELECT * FROM users WHERE name = '${req.body.name}'`;
  // ruleid: javascript-sql-injection-taint
  return connection.execute(sql);
}

function knexIntermediate(req) {
  const knex = makeKnex({});
  const prefix = "DELETE FROM users WHERE id = ";
  const value = req.params.id;
  const sql = prefix + value;
  // ruleid: javascript-sql-injection-taint
  return knex.raw(sql);
}

function sequelizeQuery(req) {
  const sequelize = new Sequelize("sqlite::memory:");
  const sql = `UPDATE users SET name = '${req.body.name}'`;
  // ruleid: javascript-sql-injection-taint
  return sequelize.query(sql);
}

function pgRawRequestQuery(req) {
  const pool = new pg.Pool();
  // ruleid: javascript-sql-injection-taint
  return pool.query(req.body.sql);
}

function mysqlRawRequestQuery(req) {
  const connection = mysql.createConnection({});
  // ruleid: javascript-sql-injection-taint
  return connection.execute(req.body.sql);
}

function unsafeConfigObject(req, pool) {
  // ruleid: javascript-sql-injection-taint
  return pool.query({text: "SELECT * FROM users WHERE id = " + req.query.id, values: []});
}

function unrelatedObject(req, searchService) {
  const text = "SELECT * FROM users WHERE name = " + req.body.name;
  // ok: javascript-sql-injection-taint
  return searchService.query(text);
}

function rawValueOnOrdinaryObject(req, ordinaryObject) {
  // ok: javascript-sql-injection-taint
  return ordinaryObject.query(req.body.filter);
}

function boundQuery(req, pool) {
  // ok: javascript-sql-injection-taint
  return pool.query("SELECT * FROM users WHERE id = $1", [req.query.id]);
}

function boundExecute(req, connection) {
  // ok: javascript-sql-injection-taint
  return connection.execute("SELECT * FROM users WHERE name = ?", [req.body.name]);
}

function boundConfigObject(req, pool) {
  // ok: javascript-sql-injection-taint
  return pool.query({text: "SELECT * FROM users WHERE id = $1", values: [req.query.id]});
}

function fixedSql(pool) {
  // ok: javascript-sql-injection-taint
  return pool.query("SELECT * FROM users WHERE active = 1");
}

function ordinaryMethod(req, processor) {
  // ok: javascript-sql-injection-taint
  return processor.execute(req.body.task);
}
