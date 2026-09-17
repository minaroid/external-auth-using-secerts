import {get} from '@loopback/rest';

/** Unauthenticated liveness probe. Reveals nothing beyond "I am running". */
export class HealthController {
  @get('/health', {
    tags: ['Operations'],
    summary: 'Liveness probe',
    responses: {'200': {description: 'Service is up'}},
  })
  health(): {status: string; service: string; time: string} {
    return {
      status: 'ok',
      service: 'tra-auth',
      time: new Date().toISOString(),
    };
  }
}
