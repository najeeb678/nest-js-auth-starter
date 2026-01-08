// import 'dotenv/config';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      stopAtFirstError: true,
      transform: true,
    }),
  );
  await app.listen(process.env.PORT ?? 4000);
  console.log('expandVariables', process.env.expandVariables);
  console.log('JWT_EXPIRES_IN', process.env.JWT_EXPIRES_IN);
}
void bootstrap();
