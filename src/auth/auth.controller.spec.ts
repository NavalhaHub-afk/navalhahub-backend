import { Test, TestingModule } from '@nestjs/testing';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';

describe('AuthController', () => {
  let controller: AuthController;
  let service: AuthService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [AuthController],
      providers: [
        {
          provide: AuthService,
          useValue: {
            signup: jest.fn(),
            login: jest.fn(),
            getCurrentUser: jest.fn(),
            logout: jest.fn(),
            requestPasswordReset: jest.fn(),
            confirmPasswordReset: jest.fn(),
          },
        },
      ],
    }).compile();

    controller = module.get<AuthController>(AuthController);
    service = module.get<AuthService>(AuthService);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });

  it('should expose the public auth contract routes', () => {
    expect(Reflect.getMetadata('path', AuthController)).toBe('api/v1/auth');
    expect(Reflect.getMetadata('method', AuthController.prototype.signup)).toBeDefined();
    expect(Reflect.getMetadata('path', AuthController.prototype.signup)).toBe('signup');
    expect(Reflect.getMetadata('method', AuthController.prototype.login)).toBeDefined();
    expect(Reflect.getMetadata('path', AuthController.prototype.login)).toBe('login');
    expect(Reflect.getMetadata('path', AuthController.prototype.getCurrentUser)).toBe('me');
    expect(Reflect.getMetadata('path', AuthController.prototype.logout)).toBe('logout');
    expect(Reflect.getMetadata('path', AuthController.prototype.requestPasswordReset)).toBe('password/reset-request');
    expect(Reflect.getMetadata('path', AuthController.prototype.confirmPasswordReset)).toBe('password/reset-confirm');
  });

  it('should delegate auth actions to the service', async () => {
    const signupDto = { email: 'user@email.com', password: '12345678', fullName: 'User Name' };
    const loginDto = { email: 'user@email.com', password: '12345678' };
    const authorization = 'Bearer token';

    await controller.signup(signupDto as any);
    await controller.login(loginDto as any);
    await controller.getCurrentUser(authorization);
    await controller.logout(authorization);
    await controller.requestPasswordReset({ email: 'user@email.com' } as any);
    await controller.confirmPasswordReset({ token: 'token', newPassword: '87654321' } as any);

    expect(service.signup).toHaveBeenCalledWith(signupDto);
    expect(service.login).toHaveBeenCalledWith(loginDto);
    expect(service.getCurrentUser).toHaveBeenCalledWith(authorization);
    expect(service.logout).toHaveBeenCalledWith(authorization);
    expect(service.requestPasswordReset).toHaveBeenCalledWith({ email: 'user@email.com' });
    expect(service.confirmPasswordReset).toHaveBeenCalledWith({ token: 'token', newPassword: '87654321' });
  });
});
