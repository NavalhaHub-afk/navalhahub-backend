import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModuleModule } from './auth-module/auth-module.module';

@Module({
  imports: [AuthModuleModule],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
