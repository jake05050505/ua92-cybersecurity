import { type Collection, type Db, type Document, MongoClient } from "mongodb";
import config from "../config.json" with { type: "json" };

export interface User extends Document {
    email: string;
    username: string;
    password: string;
}

const { hostname, port } = config.Database;

const connectionUri: string = `mongodb://${hostname}:${port}`;

const client: MongoClient = new MongoClient(connectionUri);
await client.connect();

const database: Db = client.db("secure");
export const users: Collection<User> = database.collection("accounts");
export default database;