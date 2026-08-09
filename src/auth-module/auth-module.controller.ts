import { Controller } from '@nestjs/common';
import { AuthModuleService } from './auth-module.service';

@Controller('auth-module')
export class AuthModuleController {
  constructor(private readonly authModuleService: AuthModuleService) {}
}
