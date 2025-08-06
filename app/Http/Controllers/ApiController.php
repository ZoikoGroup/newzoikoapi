<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

class ApiController extends Controller
{
    public function api_test()
    {
           return response()->json(['test-api' => 'api found']); // Return the data as JSON
    }
}
