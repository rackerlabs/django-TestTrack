# Standard library imports
import logging

# Third party imports
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.http import HttpResponseRedirect
from django.shortcuts import get_object_or_404, render
from django.urls import reverse
from django.utils import timezone
from django.utils.translation import gettext as _

from dojo.authorization.authorization import user_has_permission_or_403
from dojo.authorization.roles_permissions import Permissions

# Local application/library imports
from dojo.forms import DeleteNoteForm, NoteForm, TypedNoteForm
from dojo.models import Cred_User, Engagement, Finding, Note_Type, NoteHistory, Notes, Test

logger = logging.getLogger(__name__)


def delete_note(request, id, page, objid):
    note = get_object_or_404(Notes, id=id)
    reverse_url = None
    object_id = None

    if page == "engagement":
        obj = get_object_or_404(Engagement, id=objid)
        object_id = obj.id
        reverse_url = "view_engagement"
    elif page == "test":
        obj = get_object_or_404(Test, id=objid)
        object_id = obj.id
        reverse_url = "view_test"
    elif page == "finding":
        obj = get_object_or_404(Finding, id=objid)
        object_id = obj.id
        reverse_url = "view_finding"
    elif page == "cred":
        obj = get_object_or_404(Cred_User, id=objid)
        object_id = obj.id
        reverse_url = "view_cred_details"

    form = DeleteNoteForm(request.POST, instance=note)

    if page is None:
        raise PermissionDenied
    if str(request.user) != note.author.username:
        user_has_permission_or_403(request.user, obj, Permissions.Note_Delete)

    if form.is_valid():
        note.delete()
        messages.add_message(request,
                             messages.SUCCESS,
                             _("Note deleted."),
                             extra_tags="alert-success")
    else:
        messages.add_message(request,
                             messages.SUCCESS,
                             _("Note was not successfully deleted."),
                             extra_tags="alert-danger")

    return HttpResponseRedirect(reverse(reverse_url, args=(object_id, )))


def edit_note(request, id, page, objid):
    note = get_object_or_404(Notes, id=id)
    reverse_url = None
    object_id = None

    if page is None:
        raise PermissionDenied

    if page == "engagement":
        obj = get_object_or_404(Engagement, id=objid)
        object_id = obj.id
        reverse_url = "view_engagement"
    elif page == "test":
        obj = get_object_or_404(Test, id=objid)
        object_id = obj.id
        reverse_url = "view_test"
    elif page == "finding":
        obj = get_object_or_404(Finding, id=objid)
        object_id = obj.id
        reverse_url = "view_finding"

    if str(request.user) != note.author.username:
        user_has_permission_or_403(request.user, obj, Permissions.Note_Edit)

    note_type_activation = Note_Type.objects.filter(is_active=True).count()
    if note_type_activation:
        available_note_types = find_available_notetypes(obj, note)

    if request.method == "POST":
        if note_type_activation:
            form = TypedNoteForm(request.POST, available_note_types=available_note_types, instance=note)
        else:
            form = NoteForm(request.POST, instance=note)
        if form.is_valid():
            note = form.save(commit=False)
            note.edited = True
            note.editor = request.user
            note.edit_time = timezone.now()
            if note_type_activation:
                history = NoteHistory(note_type=note.note_type,
                                      data=note.entry,
                                      time=note.edit_time,
                                      current_editor=note.editor)
            else:
                history = NoteHistory(data=note.entry,
                                      time=note.edit_time,
                                      current_editor=note.editor)
            history.save()
            note.history.add(history)
            note.save()
            obj.last_reviewed = note.date
            obj.last_reviewed_by = request.user
            obj.save()
            form = NoteForm()
            messages.add_message(request,
                                messages.SUCCESS,
                                _("Note edited."),
                                extra_tags="alert-success")
            return HttpResponseRedirect(reverse(reverse_url, args=(object_id, )))
        messages.add_message(request,
                            messages.SUCCESS,
                            _("Note was not succesfully edited."),
                            extra_tags="alert-danger")
    else:
        if note_type_activation:
            form = TypedNoteForm(available_note_types=available_note_types, instance=note)
        else:
            form = NoteForm(instance=note)

    return render(
        request, "dojo/edit_note.html", {
            "note": note,
            "form": form,
            "page": page,
            "objid": objid,
        })


def note_history(request, id, page, objid):
    note = get_object_or_404(Notes, id=id)
    reverse_url = None
    object_id = None

    if page == "engagement":
        obj = get_object_or_404(Engagement, id=objid)
        object_id = obj.id
        reverse_url = "view_engagement"
    elif page == "test":
        obj = get_object_or_404(Test, id=objid)
        object_id = obj.id
        reverse_url = "view_test"
    elif page == "finding":
        obj = get_object_or_404(Finding, id=objid)
        object_id = obj.id
        reverse_url = "view_finding"

    if page is None:
        raise PermissionDenied
    if str(request.user) != note.author.username:
        user_has_permission_or_403(request.user, obj, Permissions.Note_View_History)

    history = note.history.all()

    if request.method == "POST":
        return HttpResponseRedirect(reverse(reverse_url, args=(object_id, )))

    return render(
        request, "dojo/view_note_history.html", {
            "history": history,
            "note": note,
            "page": page,
            "objid": objid,
        })


def find_available_notetypes(finding, editing_note):
    notes = finding.notes.all()
    single_note_types = Note_Type.objects.filter(is_single=True, is_active=True).values_list("id", flat=True)
    multiple_note_types = Note_Type.objects.filter(is_single=False, is_active=True).values_list("id", flat=True)
    available_note_types = []
    for note_type_id in multiple_note_types:
        available_note_types.append(note_type_id)
    for note_type_id in single_note_types:
        for note in notes:
            if note_type_id == note.note_type_id:
                break
        else:
            available_note_types.append(note_type_id)
    available_note_types.append(editing_note.note_type_id)
    available_note_types = list(set(available_note_types))
    return Note_Type.objects.filter(id__in=available_note_types).order_by("-id")
