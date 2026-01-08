import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { SignupDto, SigninDto } from './dtos/signup.dto';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('signup')
  async signup(@Body() signupDto: SignupDto) {
    return this.authService.signup(signupDto);
  }

  @Post('signin')
  async signin(@Body() signinDto: SigninDto) {
    return this.authService.signin(signinDto);
  }
  @Post('refresh-token')
  async refreshToken(@Body('refreshToken') refreshToken: string) {
    console.log('refreshToken11', refreshToken);
    return this.authService.refreshToken(refreshToken);
  }
}
