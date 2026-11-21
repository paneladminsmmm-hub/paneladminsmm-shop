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

async function deleteOldServices() {
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // पहले पुरानी Services की IDs निकालो
    const servicesResult = await client.query(
      "SELECT id FROM services"
    );

    const serviceIds = servicesResult.rows.map(row => row.id);

    if (serviceIds.length === 0) {
      await client.query("COMMIT");
      console.log("कोई पुरानी Service मौजूद नहीं है।");
      return;
    }

    // पुरानी Services से जुड़े Orders डिलीट करो
    const ordersResult = await client.query(
      "DELETE FROM orders WHERE service_id = ANY($1::int[])",
      [serviceIds]
    );

    // सभी पुरानी Services डिलीट करो
    const deletedServices = await client.query(
      "DELETE FROM services"
    );

    await client.query("COMMIT");

    console.log("--------------------------------");
    console.log("OLD PROVIDER CLEANUP COMPLETE");
    console.log("Deleted Services:", deletedServices.rowCount);
    console.log("Deleted Orders:", ordersResult.rowCount);
    console.log("--------------------------------");

  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Cleanup failed:", error.message);
    process.exitCode = 1;
  } finally {
    client.release();
    await pool.end();
  }
}

deleteOldServices();
