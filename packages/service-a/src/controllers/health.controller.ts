import {get} from '@loopback/rest';

export class HealthController {
  @get('/health', {
    tags: ['Operations'],
    summary: 'Liveness probe',
    responses: {'200': {description: 'Service is up'}},
  })
  health(): object {
    return {status: 'ok', service: 'service-a', time: new Date().toISOString()};
  }
}
