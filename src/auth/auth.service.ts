import {
  Injectable,
  ConflictException,
  UnauthorizedException,
  BadRequestException,
} from '@nestjs/common';
import { PrismaService } from '../prisma/prisma.service';
import { SignupDto, SigninDto } from './dtos/signup.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import ms from 'ms';

interface TokenPayload {
  sub: string;
  email: string;
}

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}
  private generateAccessToken(user: { id: string; email: string }) {
    const payload: TokenPayload = {
      sub: user.id,
      email: user.email,
    };
    return this.jwtService.sign(payload as any);
  }

  async generateAndSaveRefreshToken(user: { id: string; email: string }) {
    const refreshTokenConfig = this.configService.get<{
      secret: string;
      expiresIn: string;
    }>('refreshToken');

    if (!refreshTokenConfig?.secret || !refreshTokenConfig?.expiresIn) {
      throw new BadRequestException('Refresh token configuration is missing');
    }

    const payload: TokenPayload = {
      sub: user.id,
      email: user.email,
    };

    const expiresInRaw = refreshTokenConfig.expiresIn;

    const expiresAtMs =
      typeof expiresInRaw === 'string'
        ? (ms(expiresInRaw as any) as unknown as number)
        : Number(expiresInRaw);

    if (!Number.isFinite(expiresAtMs)) {
      throw new BadRequestException('Invalid refresh token expiration format');
    }

    const refreshToken = this.jwtService.sign<TokenPayload>(payload, {
      secret: refreshTokenConfig.secret,
      expiresIn: expiresInRaw as any,
    });

    const expiresAt = new Date(Date.now() + expiresAtMs);

    await this.prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: parseInt(user.id, 10),
        expiresAt,
      },
    });

    return refreshToken;
  }

  async refreshAccessToken(refreshToken: string) {
    if (!refreshToken || typeof refreshToken !== 'string') {
      throw new BadRequestException('Refresh token is required');
    }

    const stored = await this.prisma.refreshToken.findFirst({
      where: { token: refreshToken },
      include: { user: true },
    });

    if (!stored) {
      throw new UnauthorizedException('Invalid refresh token');
    }

    if (stored.expiresAt.getTime() < Date.now()) {
      // Token expired: delete from DB and reject
      await this.prisma.refreshToken.delete({ where: { id: stored.id } });
      throw new UnauthorizedException('Refresh token expired');
    }

    const refreshTokenConfig = this.configService.get<{ secret: string }>(
      'refreshToken',
    );
    if (!refreshTokenConfig?.secret) {
      throw new BadRequestException('Refresh token configuration is missing');
    }

    let payload: TokenPayload;
    try {
      payload = this.jwtService.verify<TokenPayload>(refreshToken, {
        secret: refreshTokenConfig.secret as any,
      });
    } catch (e: unknown) {
      // invalid token -> clean up and reject
      await this.prisma.refreshToken.delete({ where: { id: stored.id } });
      throw new UnauthorizedException(
        (e as Error)?.message || 'Invalid refresh token',
      );
    }

    // Ensure the verified payload actually matches the stored token's user
    if (
      payload.sub !== stored.user.id.toString() ||
      payload.email !== stored.user.email
    ) {
      // token doesn't match the stored record -> clean up and reject
      await this.prisma.refreshToken.delete({ where: { id: stored.id } });
      throw new UnauthorizedException('Invalid refresh token');
    }

    const accessToken = this.generateAccessToken({
      id: stored.user.id.toString(),
      email: stored.user.email,
    });

    return { accessToken };
  }

  async signup(signupDto: SignupDto) {
    const { email, password, name } = signupDto;
    // Check if user already exists

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
    });
    if (existingUser) {
      throw new ConflictException('User already exists');
    }

    // Hash password
    if (!password || typeof password !== 'string') {
      throw new BadRequestException('Invalid password');
    }
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user

    const user = await this.prisma.user.create({
      data: {
        email,
        password: hashedPassword,
        name,
      },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
      },
    });

    return {
      message: 'User signed up successfully',
      user,
    };
  }

  async signin(signinDto: SigninDto) {
    const { email, password } = signinDto;

    // Find user
    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        name: true,
        createdAt: true,
        password: true,
      },
    });
    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid credentials');
    }
    const accessToken = this.generateAccessToken({
      id: user.id.toString(),
      email: user.email,
    });
    const refreshToken = await this.generateAndSaveRefreshToken({
      id: user.id.toString(),
      email: user.email,
    });
    // Return without password
    const userWithoutPassword = {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt,
    };
    return {
      message: 'User signed in successfully',
      user: userWithoutPassword,
      accessToken,
      refreshToken,
    };
  }
}
