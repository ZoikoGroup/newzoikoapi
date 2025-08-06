<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\Plan;

class PlansController extends Controller
{
    public function plans()
    {
           return response()->json(Plan::all()); // Return all plans as JSON
    }

    public function plan_prepaid()
    {
        $prepaidPlans = Plan::ofType('prepaid')->get();
        return response()->json($prepaidPlans); // Return all plans as JSON
    }

    public function plan_postpaid()
    {
        $postpaidPlans = Plan::ofType('postpaid')->get();
        return response()->json($postpaidPlans); // Return all plans as JSON
    }

    public function plan_by_id($id)
    {
        return response()->json(Plan::find($id)); // Return all plans as JSON
    }


}
