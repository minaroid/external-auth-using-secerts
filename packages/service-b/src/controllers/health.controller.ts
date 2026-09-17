import {get} from '@loopback/rest';

export class HealthController {
  @get('/health', {
    tags: ['Operations'],
    summary: 'Liveness probe',
    responses: {'200': {description: 'OK'}},
  })
  health(): object {
    return {status: 'ok', service: 'service-b', time: new Date().toISOString()};
  }
}
