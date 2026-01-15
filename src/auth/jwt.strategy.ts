import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwtFunction } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import type { Request } from 'express';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(configService: ConfigService) {
    const secret = configService.get<string>('jwttoken.secret');
    if (!secret) throw new Error('JWT secret is not defined in config');

    const jwtFromRequest: ExtractJwtFunction = (
      req: Request,
    ): string | null => {
      const authHeader = req.headers?.authorization;
      if (!authHeader) return null;

      const [scheme, token] = authHeader.split(' ');
      if (!/^Bearer$/i.test(scheme) || !token) return null;

      return token;
    };

    super({
      jwtFromRequest,
      secretOrKey: secret,
      ignoreExpiration: false,
    });
  }

  validate(payload: { sub: string; email: string }) {
    return { userId: payload.sub, email: payload.email };
  }
}
