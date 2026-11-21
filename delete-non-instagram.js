
require("dotenv").config();

const { Pool } = require("pg");

if (!process.env.DATABASE_URL) {
  console.error("ERROR: DATABASE_URL is missing.");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false }
});

async function main() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const result = await client.query(`
      SELECT id, name, category, active
      FROM services
      ORDER BY id
    `);

    const instagram = result.rows.filter(s =>
      `${s.name || ""} ${s.category || ""}`
        .toLowerCase()
        .includes("instagram")
    );

    const others = result.rows.filter(s =>
      !`${s.name || ""} ${s.category || ""}`
        .toLowerCase()
        .includes("instagram")
    );

    console.log("========== ROYAL PANEL ==========");
    console.log("Total services:", result.rows.length);
    console.log("Instagram services to keep:", instagram.length);
    console.log("Other services to delete:", others.length);

    console.log("\nInstagram services:");
    instagram.forEach(s => console.log(s.id, s.name));

    console.log("\nOther services:");
    others.forEach(s => console.log(s.id, s.name));

    if (process.env.DELETE_NON_INSTAGRAM !== "YES") {
      await client.query("ROLLBACK");
      console.log("\nDRY RUN COMPLETE.");
      console.log("No services were deleted.");
      console.log("To confirm deletion, run:");
      console.log("DELETE_NON_INSTAGRAM=YES node delete-non-instagram.js");
      return;
    }

    const deleted = await client.query(`
      DELETE FROM services
      WHERE LOWER(
        COALESCE(name, '') || ' ' ||
        COALESCE(category, '')
      ) NOT LIKE '%instagram%'
      RETURNING id
    `);

    await client.query(`
      UPDATE services
      SET active = TRUE
      WHERE LOWER(
        COALESCE(name, '') || ' ' ||
        COALESCE(category, '')
      ) LIKE '%instagram%'
    `);

    await client.query("COMMIT");

    console.log("\nSUCCESS!");
    console.log("Deleted services:", deleted.rowCount);
    console.log("Instagram services kept:", instagram.length);
    console.log("Orders and order history were not deleted.");

  } catch (error) {
    await client.query("ROLLBACK");
    console.error("ERROR:", error.message);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

main();
