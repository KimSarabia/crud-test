'use strict';

var app = angular.module('authApp');

app.controller('profileCtrl', function() {
  console.log('profileCtrl!');
});

app.controller('mainCtrl', function($scope, $state, Auth) {

  $scope.$watch(function() {
    return Auth.currentUser;
  }, function(newVal, oldVal) {
    $scope.currentUser = newVal;
  });

  $scope.logout = () => {
    Auth.logout()
      .then(res => {
        $state.go('home');
      })
  }

});

app.controller('homeCtrl', function($scope) {
  console.log('homeCtrl!');
});



app.controller('authFormCtrl', function($scope, $state, Auth) {
  console.log('authFormCtrl!');

  $scope.currentState = $state.current.name;

  $scope.submitForm = () => {
    if($scope.currentState === 'register') {

      // register user
      if($scope.user.password !== $scope.user.password2) {
        
        $scope.user.password = '';
        $scope.user.password2 = '';
        
        alert('Passwords must match.')
      } else {
        Auth.register($scope.user)
          .then(res => {
            return Auth.login($scope.user);
          })
          .then(res => {
            $state.go('home');
          })
          .catch(res => {
            alert(res.data.error);
          });
      }
    } else {
      Auth.login($scope.user)
        .then(res => {
          $state.go('home');
        })
        .catch(res => {
          alert(res.data.error);
        })
    }
  };

});
