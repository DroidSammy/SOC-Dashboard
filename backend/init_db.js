import pg from 'pg';

const pool = new pg.Pool({
  connectionString: 'postgres://postgres:postgres@localhost:5432/postgres'
});

async function init() {
  try {
    console.log('Connecting to postgres...');
    const res = await pool.query("SELECT datname FROM pg_catalog.pg_database WHERE datname = 'soc_dashboard'");
    if (res.rows.length === 0) {
      console.log('Creating database soc_dashboard...');
      await pool.query('CREATE DATABASE soc_dashboard');
      console.log('Database created successfully.');
    } else {
      console.log('Database soc_dashboard already exists.');
    }
  } catch (err) {
    console.error('Error creating database:', err);
  } finally {
    await pool.end();
  }
}

init();
