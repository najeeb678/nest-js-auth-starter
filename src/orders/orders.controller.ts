import { Controller, Get, Request, UseGuards } from '@nestjs/common';

import { JwtAuthGuard } from 'src/auth/guards/jwt-auth.guard';
@Controller('orders')
export class OrdersController {
  @UseGuards(JwtAuthGuard)
  @Get()
  getOrders(@Request() req: any) {
    // return only the authenticated user payload to avoid circular references
    // eslint-disable-next-line @typescript-eslint/no-unsafe-member-access
    return { message: 'List of orders', user: req?.user };
  }
}
