import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, ExtractJwt } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(private configService: ConfigService) {
    // Use an explicit, typed extractor function to avoid unsafe-member-access lint warnings
    const jwtFromRequest = (req: any): string | null => {
      const authHeader = req?.headers?.authorization;
      if (!authHeader || typeof authHeader !== 'string') return null;
      const parts = authHeader.split(' ');
      if (parts.length !== 2) return null;
      const scheme = parts[0];
      const token = parts[1];
      return /^Bearer$/i.test(scheme) ? token : null;
    };

    super({
      jwtFromRequest,
      secretOrKey: configService.get<string>('jwttoken.secret') as string,
      ignoreExpiration: false,
    });
  }

  validate(payload: { sub: string; email: string }) {
    // This value will be attached to request.user
    return { userId: payload.sub, email: payload.email };
  }
}
