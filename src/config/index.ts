import dotenv from 'dotenv';
dotenv.config();

export default {
  introspectionClient: process.env.INTROSPECTION_CLIENT || null,
  introspectionClientSecret: process.env.INTROSPECTION_CLIENT_SECRET || null
}
