import { Controller, Get, Request, UseGuards } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
@Controller('orders')
export class OrdersController {
  @UseGuards(AuthGuard('jwt'))
  @Get()
  getOrders(@Request() req: any) {
    // return only the authenticated user payload to avoid circular references
    return { message: 'List of orders', user: req?.user };
  }
}
