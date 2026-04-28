import { MongoClient } from "mongodb";
import config from "../config.json" with { type: "json" };
const { hostname, port } = config.Database;
const connectionUri = `mongodb://${hostname}:${port}`;
const client = new MongoClient(connectionUri);
await client.connect();
const database = client.db("secure");
export const users = database.collection("accounts");
export default database;
