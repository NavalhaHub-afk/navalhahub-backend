import { Module } from '@nestjs/common';
import { AuthModuleService } from './auth-module.service';
import { AuthModuleController } from './auth-module.controller';

@Module({
  controllers: [AuthModuleController],
  providers: [AuthModuleService],
})
export class AuthModuleModule {}
