import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';
import { ConfigService } from '@nestjs/config';

@Controller()
export class AppController {
  constructor(
    private readonly appService: AppService,
    private readonly configService: ConfigService,
  ) {}

  @Get()
  getHello(): string {
    // const secret = this.configService.get<string>('jwttoken.secret');
    // const expiresIn = this.configService.get<string>('jwttoken.expiresIn');

    // console.log('JWT Secret:', secret);
    // console.log('Expires In:', expiresIn);
    return this.appService.getHello();
  }
}
