from django.urls import path
from .views import RegisterVoter, LoginView, CreateElection, GetElections, Results, DeleteElection, AssignCandidate, GetCandidates, RegisterCandidate, LoginCandidate, GetCandidatesByElection, Vote, ElectionResultsView

urlpatterns = [
    path('register/', RegisterVoter.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('create_election/', CreateElection.as_view(), name='create_election'),
    path('get_elections/', GetElections.as_view(), name='get_elections'),
    path('delete_election/<str:election_id>/', DeleteElection.as_view(), name='delete_election'),
    path('results/', Results.as_view(), name='results'),
    path('assign-candidate/', AssignCandidate.as_view(), name='assign_candidate'),
    path('candidates/', GetCandidates.as_view(), name='get_candidates'),
    path('candidate-register/', RegisterCandidate.as_view(), name='candidate-register'),
    path('candidate-login/', LoginCandidate.as_view(), name='candidate-login'),
    path('candidates-by-election/<str:election_id>/', GetCandidatesByElection.as_view(), name='candidates-by-election'),
    path('vote/', Vote.as_view(), name='vote'),
    path('election-results/<str:election_id>/', ElectionResultsView.as_view(), name='election-results'),
    path('api/candidates-by-election/<str:election_id>/', GetCandidatesByElection.as_view(), name='get_candidates_by_election'),

]
