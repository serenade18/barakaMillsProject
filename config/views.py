from django.conf import settings
from django.http import FileResponse, Http404
from django.views.decorators.cache import never_cache
from django.views.decorators.http import require_safe


@require_safe
@never_cache
def frontend(request):
    """Serve the React app's index.html; React Router handles the path."""
    index = settings.FRONTEND_DIST / 'index.html'
    if not index.exists():
        raise Http404('Frontend not built. Run deploy/build_frontend.sh')
    return FileResponse(index.open('rb'), content_type='text/html')
