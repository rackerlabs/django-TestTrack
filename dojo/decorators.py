import logging
from functools import wraps

from django.conf import settings
from django.db import models
from django_ratelimit import UNSAFE
from django_ratelimit.core import is_ratelimited
from django_ratelimit.exceptions import Ratelimited

from dojo.models import Dojo_User, Finding

logger = logging.getLogger(__name__)


def we_want_async(*args, func=None, **kwargs):
    from dojo.models import Dojo_User
    from dojo.utils import get_current_user

    sync = kwargs.get("sync", False)
    if sync:
        logger.debug("dojo_async_task %s: running task in the foreground as sync=True has been found as kwarg", func)
        return False

    user = kwargs.get("async_user", get_current_user())
    logger.debug("user: %s", user)

    if Dojo_User.wants_block_execution(user):
        logger.debug("dojo_async_task %s: running task in the foreground as block_execution is set to True for %s", func, user)
        return False

    logger.debug("dojo_async_task %s: no current user, running task in the background", func)
    return True


# Defect Dojo performs all tasks asynchrnonously using celery
# *unless* the user initiating the task has set block_execution to True in their usercontactinfo profile
def dojo_async_task(func):
    @wraps(func)
    def __wrapper__(*args, **kwargs):
        from dojo.utils import get_current_user
        user = get_current_user()
        kwargs["async_user"] = user
        countdown = kwargs.pop("countdown", 0)
        if we_want_async(*args, func=func, **kwargs):
            return func.apply_async(args=args, kwargs=kwargs, countdown=countdown)
        return func(*args, **kwargs)

    return __wrapper__


# decorator with parameters needs another wrapper layer
# example usage: @dojo_model_to_id(parameter=0) but defaults to parameter=0
def dojo_model_to_id(_func=None, *, parameter=0):
    # logger.debug('dec_args:' + str(dec_args))
    # logger.debug('dec_kwargs:' + str(dec_kwargs))
    # logger.debug('_func:%s', _func)

    def dojo_model_to_id_internal(func, *args, **kwargs):
        @wraps(func)
        def __wrapper__(*args, **kwargs):
            if not settings.CELERY_PASS_MODEL_BY_ID:
                return func(*args, **kwargs)

            model_or_id = get_parameter_froms_args_kwargs(args, kwargs, parameter)

            if model_or_id:
                if isinstance(model_or_id, models.Model) and we_want_async(*args, func=func, **kwargs):
                    logger.debug("converting model_or_id to id: %s", model_or_id)
                    id = model_or_id.id
                    args = list(args)
                    args[parameter] = id

            return func(*args, **kwargs)

        return __wrapper__

    if _func is None:
        # decorator called without parameters
        return dojo_model_to_id_internal
    return dojo_model_to_id_internal(_func)


# decorator with parameters needs another wrapper layer
# example usage: @dojo_model_from_id(parameter=0, model=Finding) but defaults to parameter 0 and model Finding
def dojo_model_from_id(_func=None, *, model=Finding, parameter=0):
    # logger.debug('dec_args:' + str(dec_args))
    # logger.debug('dec_kwargs:' + str(dec_kwargs))
    # logger.debug('_func:%s', _func)
    # logger.debug('model: %s', model)

    def dojo_model_from_id_internal(func, *args, **kwargs):
        @wraps(func)
        def __wrapper__(*args, **kwargs):
            if not settings.CELERY_PASS_MODEL_BY_ID:
                return func(*args, **kwargs)

            logger.debug("args:" + str(args))
            logger.debug("kwargs:" + str(kwargs))

            logger.debug("checking if we need to convert id to model: %s for parameter: %s", model.__name__, parameter)

            model_or_id = get_parameter_froms_args_kwargs(args, kwargs, parameter)

            if model_or_id:
                if not isinstance(model_or_id, models.Model) and we_want_async(*args, func=func, **kwargs):
                    logger.debug("instantiating model_or_id: %s for model: %s", model_or_id, model)
                    try:
                        instance = model.objects.get(id=model_or_id)
                    except model.DoesNotExist:
                        logger.debug("error instantiating model_or_id: %s for model: %s: DoesNotExist", model_or_id, model)
                        instance = None
                    args = list(args)
                    args[parameter] = instance
                else:
                    logger.debug("model_or_id already a model instance %s for model: %s", model_or_id, model)

            return func(*args, **kwargs)

        return __wrapper__

    if _func is None:
        # decorator called without parameters
        return dojo_model_from_id_internal
    return dojo_model_from_id_internal(_func)


def get_parameter_froms_args_kwargs(args, kwargs, parameter):
    model_or_id = None
    if isinstance(parameter, int):
        # Lookup value came as a positional argument
        args = list(args)
        if parameter >= len(args):
            raise ValueError("parameter index invalid: " + str(parameter))
        model_or_id = args[parameter]
    else:
        # Lookup value was passed as keyword argument
        model_or_id = kwargs.get(parameter, None)

    logger.debug("model_or_id: %s", model_or_id)

    if not model_or_id:
        logger.error("unable to get parameter: " + parameter)

    return model_or_id


def dojo_ratelimit(key="ip", rate=None, method=UNSAFE, *, block=False):
    def decorator(fn):
        @wraps(fn)
        def _wrapped(request, *args, **kw):
            limiter_block = getattr(settings, "RATE_LIMITER_BLOCK", block)
            limiter_rate = getattr(settings, "RATE_LIMITER_RATE", rate)
            limiter_lockout = getattr(settings, "RATE_LIMITER_ACCOUNT_LOCKOUT", False)
            old_limited = getattr(request, "limited", False)
            ratelimited = is_ratelimited(request=request, fn=fn,
                                         key=key, rate=limiter_rate, method=method,
                                         increment=True)
            request.limited = ratelimited or old_limited
            if ratelimited and limiter_block:
                if limiter_lockout:
                    username = request.POST.get("username", None)
                    if username:
                        dojo_user = Dojo_User.objects.filter(username=username).first()
                        if dojo_user:
                            Dojo_User.enable_force_password_reset(dojo_user)
                raise Ratelimited
            return fn(request, *args, **kw)
        return _wrapped
    return decorator
