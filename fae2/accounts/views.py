"""
Copyright 2014-2016 University of Illinois

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

from django.http import HttpResponse
from django.contrib.auth import logout 
from django.contrib import messages

from django.core.urlresolvers import reverse_lazy, reverse
from django.db.models import Q

from django.contrib.messages.views import SuccessMessageMixin
from django.views.generic          import TemplateView
from django.views.generic          import FormView 
from django.contrib.auth.mixins    import LoginRequiredMixin


from django.contrib.auth.models import User
from userProfiles.models import UserProfile

from django.forms.models import inlineformset_factory

from django import forms

from websiteResults.models import WebsiteReport


# Create your views here.


class Logout(TemplateView):
    template_name = 'registration/logout.html'

    def get(self, request, *args, **kwargs):
        logout(request)
        return super(Logout, self).get(request, *args, **kwargs)


class UserProfileForm(forms.Form):
    first_name          = forms.CharField(max_length=30)
    last_name           = forms.CharField(max_length=30)
    email               = forms.EmailField()
    org                 = forms.CharField(label="Organization", max_length=127, required=False)
    dept                = forms.CharField(label="Department", max_length=127, required=False)
    email_announcements = forms.BooleanField(required=False)


class UpdateUserProfileView(LoginRequiredMixin, SuccessMessageMixin, FormView):
    template_name = 'accounts/profile.html'
    form_class    = UserProfileForm

    success_url = reverse_lazy('user_profile')
    success_message = "Updated %(first_name)s %(last_name)s Profile"

    login_url = reverse_lazy('run_anonymous_report')
    redirect_field_name = "Anonymous Report"

    updated = False
    errors  = False

    def form_valid(self, form):

        user = self.request.user
        user.first_name = form.cleaned_data['first_name']
        user.last_name  = form.cleaned_data['last_name']
        user.email      = form.cleaned_data['email']
        user.save()

        profile        = user.profile
        profile.org    = form.cleaned_data['org']
        profile.dept   = form.cleaned_data['dept']
        profile.email_announcements  = form.cleaned_data['email_announcements']
        profile.save()

        return super(UpdateUserProfileView, self).form_valid(form)
  


    def get_initial(self):
        # Populate ticks in BooleanFields
        user = self.request.user
        initial = {}
        initial['first_name'] = user.first_name
        initial['last_name']  = user.last_name
        initial['email']      = user.email
        initial['org']        = user.profile.org
        initial['dept']       = user.profile.dept
        initial['email_announcements']        = user.profile.email_announcements
        return initial


# ==============================================================
#
# Status View
#
# ==============================================================

class StatusView(LoginRequiredMixin, TemplateView):
    template_name = 'accounts/status.html'

    def get_context_data(self, **kwargs):
        context = super(StatusView, self).get_context_data(**kwargs)

        reports = WebsiteReport.objects.all()

        context['initialized'] = reports.filter(Q(status='-') | Q(status='I'))
        context['processing']  = reports.filter(Q(status='A') | Q(status='S'))
        context['errors']      = reports.filter(status='E')
        
        return context  


