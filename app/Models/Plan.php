<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class Plan extends Model
{
    // Specify the table name if it's not the plural of the model name
    protected $table = 'plans';

    // Get all plans
    public static function getAllPlans()
    {
        return self::all();
    }

    public function scopeOfType($query, $type)
    {
        return $query->where('type', $type);
    }

    // Get plan by id
    public static function getPlanById($id)
    {
        return self::find($id);
    }

}
