// prisma.config.ts
import 'dotenv/config';
import { defineConfig } from 'prisma/config';

console.log('DATABASE_URL:', process.env.DATABASE_URL);

export default defineConfig({
  schema: 'prisma/schema.prisma',
  migrations: {
    path: 'prisma/migrations',
    seed: 'ts-node prisma/seed.ts',
  },
  datasource: {
    url: process.env.DATABASE_URL!,
  },
});
