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
import type ms from 'ms';

interface RefreshTokenPayload {
  sub: string;
  email: string;
  iat: number;
  exp: number;
}

@Injectable()
export class AuthService {
  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}
  private generateAccessToken(user: { id: string; email: string }) {
    return this.jwtService.sign({
      sub: user.id,
      email: user.email,
    });
  }
  private msToMs(duration: string): number {
    const match = duration.match(/^(\d+)([smhd])$/);
    if (!match) return 0;
    const value = parseInt(match[1]);
    const unit = match[2];
    switch (unit) {
      case 's':
        return value * 1000;
      case 'm':
        return value * 60 * 1000;
      case 'h':
        return value * 60 * 60 * 1000;
      case 'd':
        return value * 24 * 60 * 60 * 1000;
      default:
        return 0;
    }
  }

  async generateAndSaveRefreshToken(user: { id: string; email: string }) {
    const refreshToken = this.jwtService.sign(
      { sub: user.id, email: user.email },
      {
        secret: this.configService.get<string>('refreshToken.secret'),
        expiresIn: this.configService.get<ms.StringValue>(
          'refreshToken.expiresIn',
          '7d',
        ),
      },
    );

    const expiresIn = this.configService.get<string>(
      'refreshToken.expiresIn',
      '7d',
    );
    const expiresAt = new Date(Date.now() + this.msToMs(expiresIn));

    await this.prisma.refreshToken.create({
      data: {
        token: refreshToken,
        userId: parseInt(user.id),
        expiresAt,
      },
    });

    return refreshToken;
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
  async refreshToken(refreshToken: string) {
    try {
      console.log('token inside refreshtoken', refreshToken);
      const payload = this.jwtService.verify<RefreshTokenPayload>(
        refreshToken,
        {
          secret: this.configService.get<string>('refreshToken.secret'),
        },
      );

      console.log('payload in refresh token', payload);
      const user = await this.prisma.user.findUnique({
        where: { id: parseInt(payload.sub, 10) },
        select: {
          id: true,
          email: true,
        },
      });

      if (!user) {
        throw new UnauthorizedException('User not found');
      }
      console.log('user found', user);
      const newAccessToken = this.generateAccessToken({
        id: user.id.toString(),
        email: user.email,
      });
      const newRefreshToken = await this.generateAndSaveRefreshToken({
        id: user.id.toString(),
        email: user.email,
      });

      return {
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
      };
    } catch (error: unknown) {
      const message =
        error instanceof Error ? error.message : 'Invalid refresh token';

      throw new UnauthorizedException(message);
    }
  }
}
