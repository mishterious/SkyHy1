from django import forms
#py file currently useless; will keep for later streamlining
class UploadFileForm(forms.Form):
    title = forms.CharField(max_length=50)
    file = forms.FileField()