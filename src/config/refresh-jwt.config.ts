import { registerAs } from '@nestjs/config';

export default registerAs('refreshToken', () => ({
  secret: process.env.REFRESH_TOKEN_SECRET,
  expiresIn: process.env.REFRESH_TOKEN_EXPIRES_IN,
}));
