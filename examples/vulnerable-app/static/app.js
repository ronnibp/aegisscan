// DEMO: intentionally vulnerable JavaScript for testing AegisScan. Do NOT deploy.
const express = require("express");
const { exec } = require("child_process");
const crypto = require("crypto");

const ADMIN_PASSWORD = "Sup3rS3cretAdmin!"; // hardcoded secret
const API_TOKEN = "b7f9e2a1c8d340569a1e4f7c2b8d0a3e5c6f7182"; // high-entropy credential

function renderUser(req, res) {
  // xss: innerHTML with user data
  document.getElementById("out").innerHTML = req.query.name;
}

function calc(expr) {
  // rce: eval
  return eval(expr);
}

function runPing(host) {
  // command injection: exec with concatenation
  exec("ping -c 1 " + host);
}

function weakHash(input) {
  // weak crypto: md5
  return crypto.createHash("md5").update(input).digest("hex");
}

const agent = new https.Agent({ rejectUnauthorized: false }); // TLS disabled

app.get("/user", renderUser);
